import ts from 'typescript';
import { dottedName, isFunctionLike, lineOf, stringLiteralValue, visit } from './parse.js';
import type { ParsedFile } from './parse.js';

/**
 * Express-style route inventory.
 *
 * Scope and limits, stated plainly because several rules depend on this and
 * inherit its blind spots:
 *
 *  - Recognises `<obj>.<method>('<path>', ...)` where the path is a string
 *    literal beginning with '/'. That covers app.*, router.*, and any other
 *    receiver name, at the cost of missing routes whose path is a variable or a
 *    RegExp.
 *  - Middleware applied via `app.use` is attributed to a route only when the
 *    `use` call appears earlier in the same file, because Express middleware
 *    order is positional. Middleware registered in another module is not seen.
 *  - A handler passed by reference (`app.post('/x', createThing)`) has no
 *    inspectable body here; `handler_resolvable` is false and body-dependent
 *    rules skip it rather than guessing.
 */

const HTTP_METHODS = new Set(['get', 'post', 'put', 'patch', 'delete', 'head', 'options', 'all']);

const MUTATING_METHODS = new Set(['post', 'put', 'patch']);

/** Names that indicate an authorisation/authentication gate. */
const AUTH_MIDDLEWARE_PATTERN =
  /(^|[._])(require|ensure|check|verify|validate|is)?_?auth|authenticate|authorize|authorise|requirelogin|requireuser|requiresession|requirerole|requirescope|protect|passport|verifytoken|checkjwt|jwtcheck|ensureloggedin|isloggedin|withauth|guard/i;

/** Names that indicate rate limiting or brute-force protection. */
const RATE_LIMIT_PATTERN = /rate.?limit|ratelimiter|throttl|slow.?down|brute|bruteforce|limiter/i;

const RATE_LIMIT_MODULES = [
  'express-rate-limit',
  'express-slow-down',
  'rate-limiter-flexible',
  'express-brute',
  'koa-ratelimit',
  'fastify-rate-limit',
  '@fastify/rate-limit',
  '@upstash/ratelimit',
  'bottleneck',
  'limiter',
];

/** Validation libraries whose presence in a handler counts as a request schema. */
const VALIDATION_MODULES = [
  'zod',
  'joi',
  '@hapi/joi',
  'yup',
  'ajv',
  'superstruct',
  'valibot',
  'class-validator',
  'express-validator',
  'celebrate',
  'typebox',
  '@sinclair/typebox',
  'io-ts',
  'runtypes',
];

const VALIDATION_CALL_PATTERN =
  /^(z|joi|Joi|yup|v|t|S|Type)\.|\.(parse|safeParse|parseAsync|safeParseAsync|validateAsync|validateSync|isValid|cast|assert|create|check)$|^(celebrate|checkSchema|validationResult|matchedData|validateRequest|validateBody|validateSchema|ajv|compile)$/;

/** Paths that issue credentials, and are therefore expected to return a token. */
const AUTH_ISSUANCE_PATH_PATTERN =
  /(^|\/)(login|signin|sign-in|log-in|register|signup|sign-up|token|refresh|session|authenticate|oauth|callback|password\/reset|reset-password|forgot-password)(\/|$)/i;

/** Paths where absent rate limiting is a finding: credential and account recovery flows. */
const AUTH_ROUTE_PATH_PATTERN =
  /(^|\/)(login|signin|sign-in|log-in|register|signup|sign-up|token|refresh|authenticate|password|passwords|reset-password|forgot-password|password-reset|forgot|otp|mfa|2fa|verify-email|magic-link)(\/|$)/i;

export interface MiddlewareRef {
  /** Source text of the middleware argument, e.g. `requireAuth`. */
  text: string;
  /** Dotted callee name when the argument is a call, e.g. `passport.authenticate`. */
  name: string | null;
}

export interface GlobalMiddleware {
  /** Mount path, or null for an unmounted `app.use(fn)`. */
  mountPath: string | null;
  middleware: MiddlewareRef[];
  /** Character offset, used to respect Express's positional ordering. */
  pos: number;
}

export interface ResponsePayload {
  /** Property names of an object literal passed to res.json / res.send. */
  properties: Array<{ name: string; valueText: string; line: number; truncated: boolean }>;
  line: number;
}

export interface RouteInfo {
  method: string;
  path: string;
  line: number;
  pos: number;
  /** Middleware arguments between the path and the final handler. */
  middleware: MiddlewareRef[];
  handler: ts.Node | null;
  handler_resolvable: boolean;
  /** True when a route-level or applicable global auth middleware is present. */
  authenticated: boolean;
  /** How authentication was established, for the finding's description. */
  auth_source: 'route-middleware' | 'global-middleware' | null;
  rate_limited: boolean;
  /** Object literals returned via res.json/res.send inside the handler. */
  responses: ResponsePayload[];
  /** True when a validation-library schema is referenced by the route or handler. */
  has_validation_schema: boolean;
  /** True when the handler does hand-rolled presence/coercion checks. */
  has_manual_checks: boolean;
  /** True when the route path contains a parameter such as `:id`. */
  parameterised: boolean;
  is_mutating: boolean;
  is_auth_issuance_path: boolean;
  is_auth_route: boolean;
  /**
   * Field names the handler reads from `req.body` (e.g. `["email","password"]`).
   * Used to infer, target-agnostically, which fields a create or auth endpoint
   * expects — so verification can build a valid request body without hardcoding
   * a particular app's field names.
   */
  request_body_fields: string[];
}

export interface RouteInventory {
  routes: RouteInfo[];
  globalMiddleware: GlobalMiddleware[];
  importsRateLimitModule: boolean;
  importsValidationModule: boolean;
}

function middlewareRef(sourceFile: ts.SourceFile, node: ts.Node): MiddlewareRef {
  return { text: node.getText(sourceFile), name: dottedName(node) };
}

function matchesAny(refs: MiddlewareRef[], pattern: RegExp): boolean {
  return refs.some((ref) => pattern.test(ref.name ?? '') || pattern.test(ref.text));
}

/** Does a global middleware mount path cover this route path? */
function mountCovers(mountPath: string | null, routePath: string): boolean {
  if (mountPath === null) return true;
  if (mountPath === '/') return true;
  const normalised = mountPath.endsWith('/') ? mountPath.slice(0, -1) : mountPath;
  return routePath === normalised || routePath.startsWith(`${normalised}/`);
}

function collectResponses(sourceFile: ts.SourceFile, handler: ts.Node): ResponsePayload[] {
  const payloads: ResponsePayload[] = [];

  visit(handler, (node) => {
    if (!ts.isCallExpression(node)) return;
    const callee = dottedName(node.expression);
    if (!callee) return;
    // res.json(...), res.send(...), and res.status(401).json(...)
    if (!/(^|\.)(json|send|jsonp)$/.test(callee)) return;
    if (!/^(res|response|reply)(\.|$)/.test(callee)) return;

    const arg = node.arguments[0];
    if (!arg || !ts.isObjectLiteralExpression(arg)) return;

    const properties: ResponsePayload['properties'] = [];
    for (const prop of arg.properties) {
      let name: string | null = null;
      let valueNode: ts.Node = prop;

      if (ts.isPropertyAssignment(prop)) {
        name = ts.isIdentifier(prop.name)
          ? prop.name.text
          : ts.isStringLiteral(prop.name)
            ? prop.name.text
            : null;
        valueNode = prop.initializer;
      } else if (ts.isShorthandPropertyAssignment(prop)) {
        name = prop.name.text;
        valueNode = prop.name;
      }

      if (!name) continue;
      const valueText = valueNode.getText(sourceFile);
      properties.push({
        name,
        valueText,
        line: lineOf(sourceFile, prop),
        // A value narrowed by slice/substring/truncation exposes a prefix
        // rather than the whole secret. That changes severity, so it is tracked.
        truncated: /\.(slice|substring|substr)\s*\(|\.\.\.|\bredact|\bmask/i.test(valueText),
      });
    }

    if (properties.length > 0) payloads.push({ properties, line: lineOf(sourceFile, node) });
  });

  return payloads;
}

/**
 * Field names a handler reads from the request body: `req.body.title`,
 * `req.body?.email`, `req.body["name"]`, and destructuring `const {a,b} =
 * req.body`. Used to infer a target's create/auth payload shape without
 * hardcoding field names.
 */
function collectRequestBodyFields(sourceFile: ts.SourceFile, handler: ts.Node): string[] {
  const fields = new Set<string>();

  visit(handler, (node) => {
    // req.body.<field> / req.body?.<field>
    if (ts.isPropertyAccessExpression(node)) {
      const base = node.expression;
      const baseName = dottedName(base);
      if (baseName && /(^|\.)req(uest)?\.body$/.test(baseName)) fields.add(node.name.text);
      return;
    }
    // req.body["<field>"]
    if (ts.isElementAccessExpression(node)) {
      const baseName = dottedName(node.expression);
      if (baseName && /(^|\.)req(uest)?\.body$/.test(baseName) && node.argumentExpression) {
        const key = stringLiteralValue(node.argumentExpression);
        if (key) fields.add(key);
      }
      return;
    }
    // const { a, b } = req.body
    if (ts.isVariableDeclaration(node) && node.initializer && ts.isObjectBindingPattern(node.name)) {
      const initName = dottedName(node.initializer);
      if (initName && /(^|\.)req(uest)?\.body$/.test(initName)) {
        for (const element of node.name.elements) {
          const key = element.propertyName ?? element.name;
          if (ts.isIdentifier(key)) fields.add(key.text);
        }
      }
    }
  });

  return [...fields];
}

function detectValidation(sourceFile: ts.SourceFile, handler: ts.Node | null, middleware: MiddlewareRef[]): boolean {
  if (matchesAny(middleware, /valid|celebrate|checkSchema|schema/i)) return true;
  if (!handler) return false;

  let found = false;
  visit(handler, (node) => {
    if (found) return;
    if (!ts.isCallExpression(node)) return;
    const callee = dottedName(node.expression);
    if (callee && VALIDATION_CALL_PATTERN.test(callee)) found = true;
  });
  return found;
}

function detectManualChecks(sourceFile: ts.SourceFile, handler: ts.Node | null): boolean {
  if (!handler) return false;
  const text = handler.getText(sourceFile);
  // Hand-rolled guards: a 400 response, presence tests, or explicit coercion.
  return (
    /status\(\s*4\d\d\s*\)/.test(text) ||
    /\btypeof\b/.test(text) ||
    /\b(String|Number|Boolean)\s*\(\s*req\./.test(text)
  );
}

export function buildRouteInventory(parsed: ParsedFile): RouteInventory {
  const { sourceFile } = parsed;
  const globalMiddleware: GlobalMiddleware[] = [];
  const rawRoutes: Array<Omit<RouteInfo, 'authenticated' | 'auth_source' | 'rate_limited'>> = [];

  visit(sourceFile, (node) => {
    if (!ts.isCallExpression(node)) return;
    if (!ts.isPropertyAccessExpression(node.expression)) return;

    const method = node.expression.name.text.toLowerCase();
    const args = node.arguments;
    if (args.length === 0) return;

    if (method === 'use') {
      const first = args[0]!;
      const mountPath = stringLiteralValue(first);
      const middlewareArgs = mountPath === null ? [...args] : args.slice(1);
      globalMiddleware.push({
        mountPath,
        middleware: middlewareArgs.map((a) => middlewareRef(sourceFile, a)),
        pos: node.getStart(sourceFile),
      });
      return;
    }

    if (!HTTP_METHODS.has(method)) return;

    const path = stringLiteralValue(args[0]!);
    // Requiring a leading slash keeps this from matching things like
    // `promise.all(...)` or `array.get('key')`.
    if (path === null || !path.startsWith('/')) return;

    const rest = args.slice(1);
    if (rest.length === 0) return;

    const last = rest.at(-1)!;
    const handlerIsInline = isFunctionLike(last);
    const middleware = rest.slice(0, rest.length - 1).map((a) => middlewareRef(sourceFile, a));

    // A trailing identifier is a handler by reference, not middleware.
    const handler = handlerIsInline ? last : null;

    rawRoutes.push({
      method,
      path,
      line: lineOf(sourceFile, node),
      pos: node.getStart(sourceFile),
      middleware,
      handler,
      handler_resolvable: handlerIsInline,
      responses: handler ? collectResponses(sourceFile, handler) : [],
      has_validation_schema: detectValidation(sourceFile, handler, middleware),
      has_manual_checks: detectManualChecks(sourceFile, handler),
      parameterised: /:[A-Za-z_][\w-]*/.test(path) || path.includes('*'),
      is_mutating: MUTATING_METHODS.has(method),
      is_auth_issuance_path: AUTH_ISSUANCE_PATH_PATTERN.test(path),
      is_auth_route: AUTH_ROUTE_PATH_PATTERN.test(path),
      request_body_fields: handler ? collectRequestBodyFields(sourceFile, handler) : [],
    });
  });

  const modules = new Set(
    (function () {
      const found: string[] = [];
      visit(sourceFile, (node) => {
        if (ts.isImportDeclaration(node)) {
          const v = stringLiteralValue(node.moduleSpecifier);
          if (v) found.push(v);
        } else if (ts.isCallExpression(node) && dottedName(node.expression) === 'require') {
          const v = node.arguments[0] ? stringLiteralValue(node.arguments[0]) : null;
          if (v) found.push(v);
        }
      });
      return found;
    })(),
  );

  const importsRateLimitModule = RATE_LIMIT_MODULES.some((m) => modules.has(m));
  const importsValidationModule = VALIDATION_MODULES.some((m) => modules.has(m));

  const routes: RouteInfo[] = rawRoutes.map((route) => {
    const routeLevelAuth = matchesAny(route.middleware, AUTH_MIDDLEWARE_PATTERN);

    // Only `use` calls registered before this route can apply to it.
    const applicableGlobals = globalMiddleware.filter(
      (g) => g.pos < route.pos && mountCovers(g.mountPath, route.path),
    );
    const globalAuth = applicableGlobals.some((g) => matchesAny(g.middleware, AUTH_MIDDLEWARE_PATTERN));

    const rateLimited =
      matchesAny(route.middleware, RATE_LIMIT_PATTERN) ||
      applicableGlobals.some((g) => matchesAny(g.middleware, RATE_LIMIT_PATTERN));

    return {
      ...route,
      authenticated: routeLevelAuth || globalAuth,
      auth_source: routeLevelAuth ? 'route-middleware' : globalAuth ? 'global-middleware' : null,
      rate_limited: rateLimited,
    };
  });

  return { routes, globalMiddleware, importsRateLimitModule, importsValidationModule };
}
