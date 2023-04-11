'use strict';

var bodyParser = require('body-parser');
var compression = require('compression');
var cors = require('cors');
var express = require('express');
var mongoose = require('mongoose');
var dotenv = require('dotenv');

const dangerouslyDisableDefaultSrc = Symbol("dangerouslyDisableDefaultSrc");
const DEFAULT_DIRECTIVES = {
	"default-src": ["'self'"],
	"base-uri": ["'self'"],
	"font-src": ["'self'", "https:", "data:"],
	"form-action": ["'self'"],
	"frame-ancestors": ["'self'"],
	"img-src": ["'self'", "data:"],
	"object-src": ["'none'"],
	"script-src": ["'self'"],
	"script-src-attr": ["'none'"],
	"style-src": ["'self'", "https:", "'unsafe-inline'"],
	"upgrade-insecure-requests": []
};
const getDefaultDirectives = () => Object.assign({}, DEFAULT_DIRECTIVES);
const dashify = str => str.replace(/[A-Z]/g, capitalLetter => "-" + capitalLetter.toLowerCase());
const isDirectiveValueInvalid = directiveValue => /;|,/.test(directiveValue);
const has = (obj, key) => Object.prototype.hasOwnProperty.call(obj, key);
function normalizeDirectives(options) {
	const defaultDirectives = getDefaultDirectives();
	const {useDefaults = true, directives: rawDirectives = defaultDirectives} = options;
	const result = new Map();
	const directiveNamesSeen = new Set();
	const directivesExplicitlyDisabled = new Set();
	for (const rawDirectiveName in rawDirectives) {
		if (!has(rawDirectives, rawDirectiveName)) {
			continue
		}
		if (rawDirectiveName.length === 0 || /[^a-zA-Z0-9-]/.test(rawDirectiveName)) {
			throw new Error(`Content-Security-Policy received an invalid directive name ${JSON.stringify(rawDirectiveName)}`)
		}
		const directiveName = dashify(rawDirectiveName);
		if (directiveNamesSeen.has(directiveName)) {
			throw new Error(`Content-Security-Policy received a duplicate directive ${JSON.stringify(directiveName)}`)
		}
		directiveNamesSeen.add(directiveName);
		const rawDirectiveValue = rawDirectives[rawDirectiveName];
		let directiveValue;
		if (rawDirectiveValue === null) {
			if (directiveName === "default-src") {
				throw new Error("Content-Security-Policy needs a default-src but it was set to `null`. If you really want to disable it, set it to `contentSecurityPolicy.dangerouslyDisableDefaultSrc`.")
			}
			directivesExplicitlyDisabled.add(directiveName);
			continue
		} else if (typeof rawDirectiveValue === "string") {
			directiveValue = [rawDirectiveValue];
		} else if (!rawDirectiveValue) {
			throw new Error(`Content-Security-Policy received an invalid directive value for ${JSON.stringify(directiveName)}`)
		} else if (rawDirectiveValue === dangerouslyDisableDefaultSrc) {
			if (directiveName === "default-src") {
				directivesExplicitlyDisabled.add("default-src");
				continue
			} else {
				throw new Error(`Content-Security-Policy: tried to disable ${JSON.stringify(directiveName)} as if it were default-src; simply omit the key`)
			}
		} else {
			directiveValue = rawDirectiveValue;
		}
		for (const element of directiveValue) {
			if (typeof element === "string" && isDirectiveValueInvalid(element)) {
				throw new Error(`Content-Security-Policy received an invalid directive value for ${JSON.stringify(directiveName)}`)
			}
		}
		result.set(directiveName, directiveValue);
	}
	if (useDefaults) {
		Object.entries(defaultDirectives).forEach(([defaultDirectiveName, defaultDirectiveValue]) => {
			if (!result.has(defaultDirectiveName) && !directivesExplicitlyDisabled.has(defaultDirectiveName)) {
				result.set(defaultDirectiveName, defaultDirectiveValue);
			}
		});
	}
	if (!result.size) {
		throw new Error("Content-Security-Policy has no directives. Either set some or disable the header")
	}
	if (!result.has("default-src") && !directivesExplicitlyDisabled.has("default-src")) {
		throw new Error("Content-Security-Policy needs a default-src but none was provided. If you really want to disable it, set it to `contentSecurityPolicy.dangerouslyDisableDefaultSrc`.")
	}
	return result
}
function getHeaderValue(req, res, normalizedDirectives) {
	let err;
	const result = [];
	normalizedDirectives.forEach((rawDirectiveValue, directiveName) => {
		let directiveValue = "";
		for (const element of rawDirectiveValue) {
			directiveValue += " " + (element instanceof Function ? element(req, res) : element);
		}
		if (!directiveValue) {
			result.push(directiveName);
		} else if (isDirectiveValueInvalid(directiveValue)) {
			err = new Error(`Content-Security-Policy received an invalid directive value for ${JSON.stringify(directiveName)}`);
		} else {
			result.push(`${directiveName}${directiveValue}`);
		}
	});
	return err ? err : result.join(";")
}
const contentSecurityPolicy = function contentSecurityPolicy(options = {}) {
	const headerName = options.reportOnly ? "Content-Security-Policy-Report-Only" : "Content-Security-Policy";
	const normalizedDirectives = normalizeDirectives(options);
	return function contentSecurityPolicyMiddleware(req, res, next) {
		const result = getHeaderValue(req, res, normalizedDirectives);
		if (result instanceof Error) {
			next(result);
		} else {
			res.setHeader(headerName, result);
			next();
		}
	}
};
contentSecurityPolicy.getDefaultDirectives = getDefaultDirectives;
contentSecurityPolicy.dangerouslyDisableDefaultSrc = dangerouslyDisableDefaultSrc;

const ALLOWED_POLICIES$2 = new Set(["require-corp", "credentialless"]);
function getHeaderValueFromOptions$7({policy = "require-corp"}) {
	if (ALLOWED_POLICIES$2.has(policy)) {
		return policy
	} else {
		throw new Error(`Cross-Origin-Embedder-Policy does not support the ${JSON.stringify(policy)} policy`)
	}
}
function crossOriginEmbedderPolicy(options = {}) {
	const headerValue = getHeaderValueFromOptions$7(options);
	return function crossOriginEmbedderPolicyMiddleware(_req, res, next) {
		res.setHeader("Cross-Origin-Embedder-Policy", headerValue);
		next();
	}
}

const ALLOWED_POLICIES$1 = new Set(["same-origin", "same-origin-allow-popups", "unsafe-none"]);
function getHeaderValueFromOptions$6({policy = "same-origin"}) {
	if (ALLOWED_POLICIES$1.has(policy)) {
		return policy
	} else {
		throw new Error(`Cross-Origin-Opener-Policy does not support the ${JSON.stringify(policy)} policy`)
	}
}
function crossOriginOpenerPolicy(options = {}) {
	const headerValue = getHeaderValueFromOptions$6(options);
	return function crossOriginOpenerPolicyMiddleware(_req, res, next) {
		res.setHeader("Cross-Origin-Opener-Policy", headerValue);
		next();
	}
}

const ALLOWED_POLICIES = new Set(["same-origin", "same-site", "cross-origin"]);
function getHeaderValueFromOptions$5({policy = "same-origin"}) {
	if (ALLOWED_POLICIES.has(policy)) {
		return policy
	} else {
		throw new Error(`Cross-Origin-Resource-Policy does not support the ${JSON.stringify(policy)} policy`)
	}
}
function crossOriginResourcePolicy(options = {}) {
	const headerValue = getHeaderValueFromOptions$5(options);
	return function crossOriginResourcePolicyMiddleware(_req, res, next) {
		res.setHeader("Cross-Origin-Resource-Policy", headerValue);
		next();
	}
}

function parseMaxAge$1(value = 0) {
	if (value >= 0 && Number.isFinite(value)) {
		return Math.floor(value)
	} else {
		throw new Error(`Expect-CT: ${JSON.stringify(value)} is not a valid value for maxAge. Please choose a positive integer.`)
	}
}
function getHeaderValueFromOptions$4(options) {
	const directives = [`max-age=${parseMaxAge$1(options.maxAge)}`];
	if (options.enforce) {
		directives.push("enforce");
	}
	if (options.reportUri) {
		directives.push(`report-uri="${options.reportUri}"`);
	}
	return directives.join(", ")
}
function expectCt(options = {}) {
	const headerValue = getHeaderValueFromOptions$4(options);
	return function expectCtMiddleware(_req, res, next) {
		res.setHeader("Expect-CT", headerValue);
		next();
	}
}

function originAgentCluster() {
	return function originAgentClusterMiddleware(_req, res, next) {
		res.setHeader("Origin-Agent-Cluster", "?1");
		next();
	}
}

const ALLOWED_TOKENS = new Set(["no-referrer", "no-referrer-when-downgrade", "same-origin", "origin", "strict-origin", "origin-when-cross-origin", "strict-origin-when-cross-origin", "unsafe-url", ""]);
function getHeaderValueFromOptions$3({policy = ["no-referrer"]}) {
	const tokens = typeof policy === "string" ? [policy] : policy;
	if (tokens.length === 0) {
		throw new Error("Referrer-Policy received no policy tokens")
	}
	const tokensSeen = new Set();
	tokens.forEach(token => {
		if (!ALLOWED_TOKENS.has(token)) {
			throw new Error(`Referrer-Policy received an unexpected policy token ${JSON.stringify(token)}`)
		} else if (tokensSeen.has(token)) {
			throw new Error(`Referrer-Policy received a duplicate policy token ${JSON.stringify(token)}`)
		}
		tokensSeen.add(token);
	});
	return tokens.join(",")
}
function referrerPolicy(options = {}) {
	const headerValue = getHeaderValueFromOptions$3(options);
	return function referrerPolicyMiddleware(_req, res, next) {
		res.setHeader("Referrer-Policy", headerValue);
		next();
	}
}

const DEFAULT_MAX_AGE = 180 * 24 * 60 * 60;
function parseMaxAge(value = DEFAULT_MAX_AGE) {
	if (value >= 0 && Number.isFinite(value)) {
		return Math.floor(value)
	} else {
		throw new Error(`Strict-Transport-Security: ${JSON.stringify(value)} is not a valid value for maxAge. Please choose a positive integer.`)
	}
}
function getHeaderValueFromOptions$2(options) {
	if ("maxage" in options) {
		throw new Error("Strict-Transport-Security received an unsupported property, `maxage`. Did you mean to pass `maxAge`?")
	}
	if ("includeSubdomains" in options) {
		console.warn('Strict-Transport-Security middleware should use `includeSubDomains` instead of `includeSubdomains`. (The correct one has an uppercase "D".)');
	}
	if ("setIf" in options) {
		console.warn("Strict-Transport-Security middleware no longer supports the `setIf` parameter. See the documentation and <https://github.com/helmetjs/helmet/wiki/Conditionally-using-middleware> if you need help replicating this behavior.");
	}
	const directives = [`max-age=${parseMaxAge(options.maxAge)}`];
	if (options.includeSubDomains === undefined || options.includeSubDomains) {
		directives.push("includeSubDomains");
	}
	if (options.preload) {
		directives.push("preload");
	}
	return directives.join("; ")
}
function strictTransportSecurity(options = {}) {
	const headerValue = getHeaderValueFromOptions$2(options);
	return function strictTransportSecurityMiddleware(_req, res, next) {
		res.setHeader("Strict-Transport-Security", headerValue);
		next();
	}
}

function xContentTypeOptions() {
	return function xContentTypeOptionsMiddleware(_req, res, next) {
		res.setHeader("X-Content-Type-Options", "nosniff");
		next();
	}
}

function xDnsPrefetchControl(options = {}) {
	const headerValue = options.allow ? "on" : "off";
	return function xDnsPrefetchControlMiddleware(_req, res, next) {
		res.setHeader("X-DNS-Prefetch-Control", headerValue);
		next();
	}
}

function xDownloadOptions() {
	return function xDownloadOptionsMiddleware(_req, res, next) {
		res.setHeader("X-Download-Options", "noopen");
		next();
	}
}

function getHeaderValueFromOptions$1({action = "sameorigin"}) {
	const normalizedAction = typeof action === "string" ? action.toUpperCase() : action;
	switch (normalizedAction) {
		case "SAME-ORIGIN":
			return "SAMEORIGIN"
		case "DENY":
		case "SAMEORIGIN":
			return normalizedAction
		default:
			throw new Error(`X-Frame-Options received an invalid action ${JSON.stringify(action)}`)
	}
}
function xFrameOptions(options = {}) {
	const headerValue = getHeaderValueFromOptions$1(options);
	return function xFrameOptionsMiddleware(_req, res, next) {
		res.setHeader("X-Frame-Options", headerValue);
		next();
	}
}

const ALLOWED_PERMITTED_POLICIES = new Set(["none", "master-only", "by-content-type", "all"]);
function getHeaderValueFromOptions({permittedPolicies = "none"}) {
	if (ALLOWED_PERMITTED_POLICIES.has(permittedPolicies)) {
		return permittedPolicies
	} else {
		throw new Error(`X-Permitted-Cross-Domain-Policies does not support ${JSON.stringify(permittedPolicies)}`)
	}
}
function xPermittedCrossDomainPolicies(options = {}) {
	const headerValue = getHeaderValueFromOptions(options);
	return function xPermittedCrossDomainPoliciesMiddleware(_req, res, next) {
		res.setHeader("X-Permitted-Cross-Domain-Policies", headerValue);
		next();
	}
}

function xPoweredBy() {
	return function xPoweredByMiddleware(_req, res, next) {
		res.removeHeader("X-Powered-By");
		next();
	}
}

function xXssProtection() {
	return function xXssProtectionMiddleware(_req, res, next) {
		res.setHeader("X-XSS-Protection", "0");
		next();
	}
}

function getArgs(option, middlewareConfig = {}) {
	switch (option) {
		case undefined:
		case true:
			return []
		case false:
			return null
		default:
			if (middlewareConfig.takesOptions === false) {
				console.warn(`${middlewareConfig.name} does not take options. Remove the property to silence this warning.`);
				return []
			} else {
				return [option]
			}
	}
}
function getMiddlewareFunctionsFromOptions(options) {
	const result = [];
	const contentSecurityPolicyArgs = getArgs(options.contentSecurityPolicy);
	if (contentSecurityPolicyArgs) {
		result.push(contentSecurityPolicy(...contentSecurityPolicyArgs));
	}
	const crossOriginEmbedderPolicyArgs = getArgs(options.crossOriginEmbedderPolicy);
	if (crossOriginEmbedderPolicyArgs) {
		result.push(crossOriginEmbedderPolicy(...crossOriginEmbedderPolicyArgs));
	}
	const crossOriginOpenerPolicyArgs = getArgs(options.crossOriginOpenerPolicy);
	if (crossOriginOpenerPolicyArgs) {
		result.push(crossOriginOpenerPolicy(...crossOriginOpenerPolicyArgs));
	}
	const crossOriginResourcePolicyArgs = getArgs(options.crossOriginResourcePolicy);
	if (crossOriginResourcePolicyArgs) {
		result.push(crossOriginResourcePolicy(...crossOriginResourcePolicyArgs));
	}
	const xDnsPrefetchControlArgs = getArgs(options.dnsPrefetchControl);
	if (xDnsPrefetchControlArgs) {
		result.push(xDnsPrefetchControl(...xDnsPrefetchControlArgs));
	}
	const expectCtArgs = options.expectCt && getArgs(options.expectCt);
	if (expectCtArgs) {
		result.push(expectCt(...expectCtArgs));
	}
	const xFrameOptionsArgs = getArgs(options.frameguard);
	if (xFrameOptionsArgs) {
		result.push(xFrameOptions(...xFrameOptionsArgs));
	}
	const xPoweredByArgs = getArgs(options.hidePoweredBy, {
		name: "hidePoweredBy",
		takesOptions: false
	});
	if (xPoweredByArgs) {
		result.push(xPoweredBy());
	}
	const strictTransportSecurityArgs = getArgs(options.hsts);
	if (strictTransportSecurityArgs) {
		result.push(strictTransportSecurity(...strictTransportSecurityArgs));
	}
	const xDownloadOptionsArgs = getArgs(options.ieNoOpen, {
		name: "ieNoOpen",
		takesOptions: false
	});
	if (xDownloadOptionsArgs) {
		result.push(xDownloadOptions());
	}
	const xContentTypeOptionsArgs = getArgs(options.noSniff, {
		name: "noSniff",
		takesOptions: false
	});
	if (xContentTypeOptionsArgs) {
		result.push(xContentTypeOptions());
	}
	const originAgentClusterArgs = getArgs(options.originAgentCluster, {
		name: "originAgentCluster",
		takesOptions: false
	});
	if (originAgentClusterArgs) {
		result.push(originAgentCluster());
	}
	const xPermittedCrossDomainPoliciesArgs = getArgs(options.permittedCrossDomainPolicies);
	if (xPermittedCrossDomainPoliciesArgs) {
		result.push(xPermittedCrossDomainPolicies(...xPermittedCrossDomainPoliciesArgs));
	}
	const referrerPolicyArgs = getArgs(options.referrerPolicy);
	if (referrerPolicyArgs) {
		result.push(referrerPolicy(...referrerPolicyArgs));
	}
	const xXssProtectionArgs = getArgs(options.xssFilter, {
		name: "xssFilter",
		takesOptions: false
	});
	if (xXssProtectionArgs) {
		result.push(xXssProtection());
	}
	return result
}
const helmet = Object.assign(
	function helmet(options = {}) {
		var _a;
		// People should be able to pass an options object with no prototype,
		// so we want this optional chaining.
		// eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
		if (((_a = options.constructor) === null || _a === void 0 ? void 0 : _a.name) === "IncomingMessage") {
			throw new Error("It appears you have done something like `app.use(helmet)`, but it should be `app.use(helmet())`.")
		}
		const middlewareFunctions = getMiddlewareFunctionsFromOptions(options);
		return function helmetMiddleware(req, res, next) {
			let middlewareIndex = 0
			;(function internalNext(err) {
				if (err) {
					next(err);
					return
				}
				const middlewareFunction = middlewareFunctions[middlewareIndex];
				if (middlewareFunction) {
					middlewareIndex++;
					middlewareFunction(req, res, internalNext);
				} else {
					next();
				}
			})();
		}
	},
	{
		contentSecurityPolicy,
		crossOriginEmbedderPolicy,
		crossOriginOpenerPolicy,
		crossOriginResourcePolicy,
		dnsPrefetchControl: xDnsPrefetchControl,
		expectCt,
		frameguard: xFrameOptions,
		hidePoweredBy: xPoweredBy,
		hsts: strictTransportSecurity,
		ieNoOpen: xDownloadOptions,
		noSniff: xContentTypeOptions,
		originAgentCluster,
		permittedCrossDomainPolicies: xPermittedCrossDomainPolicies,
		referrerPolicy,
		xssFilter: xXssProtection
	}
);

const LabSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
    },
});
const DisciplineSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
    },
    teachers: {
        type: String,
        required: true,
    },
    teacherEmail: {
        type: String,
        required: true,
    },
    labs: {
        type: [LabSchema],
        required: true,
    },
});
const SpecialitieSchema = new mongoose.Schema({
    id: {
        type: String,
        required: true,
    },
    name: {
        type: String,
        required: true,
    },
    disciplines: {
        type: [DisciplineSchema],
        required: true,
    },
});
const UniversitySchema = new mongoose.Schema({
    _id: {
        type: Number,
        required: true,
    },
    id: {
        type: String,
        required: true,
    },
    name: {
        type: String,
        required: true,
    },
    abbr: {
        type: String,
        required: true,
    },
    specialities: {
        type: [SpecialitieSchema],
        required: true,
    },
});
const UniversityModel = mongoose.models.University ?? mongoose.model('University', UniversitySchema);

const get = async (req, res) => {
    try {
        const data = await UniversityModel.find().lean();
        return res.send(data);
    }
    catch (error) {
        return res.send();
    }
    finally {
        res.end();
    }
};

const universityRouter = express.Router();
universityRouter.get('/', get);

const apiRouter = express.Router();
apiRouter.use('/university', universityRouter);

const server = express();
try {
    server.use(bodyParser.urlencoded({ extended: true }));
    server.use(bodyParser.json());
    server.use(compression());
    server.use(cors());
    server.use(helmet({
        contentSecurityPolicy: false,
    }));
    server.use('/api', apiRouter);
    console.log('[SERVER] Initialized');
}
catch (error) {
    console.error(error);
}

dotenv.config();
// global
const PORT = process.env.PORT ?? 4000;
// database
// database
const DB_USER = process.env.DB_USER;
const DB_PASS = process.env.DB_PASS;
const DB_NAME = process.env.DB_NAME;
const DB_CONNSTR = process.env.DB_CONNSTR
    .replace('<user>', DB_USER)
    .replace('<pass>', DB_PASS)
    .replace('<db>', DB_NAME);

mongoose.set('strictQuery', false);
class Database {
    static instance = null;
    constructor() {
        if (Database.instance === null)
            Database.instance = this;
        return Database.instance;
    }
    isConnected = () => mongoose.connection.readyState === 1;
    connect = async () => {
        const defaultReturn = this.isConnected;
        if (this.isConnected())
            return defaultReturn;
        console.log('[DB] Connecting...');
        try {
            await mongoose.connect(DB_CONNSTR);
            console.log(`[DB] Connected to "${DB_NAME}"`);
        }
        catch (error) {
            console.error('[DB] Connection error');
            console.error(error);
        }
        return defaultReturn;
    };
}

const locale = 'uk-UA';
const timeZone = 'Europe/Kiev';
const getCurrentTimeString = () => new Date().toLocaleTimeString(locale, {
    timeZone,
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
});

const mainListen = () => {
    try {
        console.log(`[SERVER] | ${getCurrentTimeString()} Listening at ${PORT}`);
    }
    catch (error) {
        console.error(error);
    }
};

const start = async () => {
    const database = new Database();
    void server.listen(PORT, mainListen);
    void database.connect();
};
void start();
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXguanMiLCJzb3VyY2VzIjpbIi4uL25vZGVfbW9kdWxlcy8ucG5wbS9oZWxtZXRANi4xLjUvbm9kZV9tb2R1bGVzL2hlbG1ldC9pbmRleC5tanMiLCIuLi9zcmMvRGF0YWJhc2UvbW9kZWxzL1VuaXZlcnNpdHkudHMiLCIuLi9zcmMvYXBpL2NvbnRyb2xsZXJzL3VuaXZlcnNpdHkvZ2V0LnRzIiwiLi4vc3JjL2FwaS9yb3V0ZXMvdW5pdmVyc2l0eVJvdXRlci50cyIsIi4uL3NyYy9hcGkvYXBpUm91dGVyLnRzIiwiLi4vc3JjL3NlcnZlci50cyIsIi4uL3NyYy9jb25maWcudHMiLCIuLi9zcmMvRGF0YWJhc2UvRGF0YWJhc2UudHMiLCIuLi9zcmMvdXRpbHMvZGF0ZS50cyIsIi4uL3NyYy9hcGkvY29udHJvbGxlcnMvbWFpbi9tYWluTGlzdGVuLnRzIiwiLi4vc3JjL2luZGV4LnRzIl0sInNvdXJjZXNDb250ZW50IjpbImNvbnN0IGRhbmdlcm91c2x5RGlzYWJsZURlZmF1bHRTcmMgPSBTeW1ib2woXCJkYW5nZXJvdXNseURpc2FibGVEZWZhdWx0U3JjXCIpXG5jb25zdCBERUZBVUxUX0RJUkVDVElWRVMgPSB7XG5cdFwiZGVmYXVsdC1zcmNcIjogW1wiJ3NlbGYnXCJdLFxuXHRcImJhc2UtdXJpXCI6IFtcIidzZWxmJ1wiXSxcblx0XCJmb250LXNyY1wiOiBbXCInc2VsZidcIiwgXCJodHRwczpcIiwgXCJkYXRhOlwiXSxcblx0XCJmb3JtLWFjdGlvblwiOiBbXCInc2VsZidcIl0sXG5cdFwiZnJhbWUtYW5jZXN0b3JzXCI6IFtcIidzZWxmJ1wiXSxcblx0XCJpbWctc3JjXCI6IFtcIidzZWxmJ1wiLCBcImRhdGE6XCJdLFxuXHRcIm9iamVjdC1zcmNcIjogW1wiJ25vbmUnXCJdLFxuXHRcInNjcmlwdC1zcmNcIjogW1wiJ3NlbGYnXCJdLFxuXHRcInNjcmlwdC1zcmMtYXR0clwiOiBbXCInbm9uZSdcIl0sXG5cdFwic3R5bGUtc3JjXCI6IFtcIidzZWxmJ1wiLCBcImh0dHBzOlwiLCBcIid1bnNhZmUtaW5saW5lJ1wiXSxcblx0XCJ1cGdyYWRlLWluc2VjdXJlLXJlcXVlc3RzXCI6IFtdXG59XG5jb25zdCBnZXREZWZhdWx0RGlyZWN0aXZlcyA9ICgpID0+IE9iamVjdC5hc3NpZ24oe30sIERFRkFVTFRfRElSRUNUSVZFUylcbmNvbnN0IGRhc2hpZnkgPSBzdHIgPT4gc3RyLnJlcGxhY2UoL1tBLVpdL2csIGNhcGl0YWxMZXR0ZXIgPT4gXCItXCIgKyBjYXBpdGFsTGV0dGVyLnRvTG93ZXJDYXNlKCkpXG5jb25zdCBpc0RpcmVjdGl2ZVZhbHVlSW52YWxpZCA9IGRpcmVjdGl2ZVZhbHVlID0+IC87fCwvLnRlc3QoZGlyZWN0aXZlVmFsdWUpXG5jb25zdCBoYXMgPSAob2JqLCBrZXkpID0+IE9iamVjdC5wcm90b3R5cGUuaGFzT3duUHJvcGVydHkuY2FsbChvYmosIGtleSlcbmZ1bmN0aW9uIG5vcm1hbGl6ZURpcmVjdGl2ZXMob3B0aW9ucykge1xuXHRjb25zdCBkZWZhdWx0RGlyZWN0aXZlcyA9IGdldERlZmF1bHREaXJlY3RpdmVzKClcblx0Y29uc3Qge3VzZURlZmF1bHRzID0gdHJ1ZSwgZGlyZWN0aXZlczogcmF3RGlyZWN0aXZlcyA9IGRlZmF1bHREaXJlY3RpdmVzfSA9IG9wdGlvbnNcblx0Y29uc3QgcmVzdWx0ID0gbmV3IE1hcCgpXG5cdGNvbnN0IGRpcmVjdGl2ZU5hbWVzU2VlbiA9IG5ldyBTZXQoKVxuXHRjb25zdCBkaXJlY3RpdmVzRXhwbGljaXRseURpc2FibGVkID0gbmV3IFNldCgpXG5cdGZvciAoY29uc3QgcmF3RGlyZWN0aXZlTmFtZSBpbiByYXdEaXJlY3RpdmVzKSB7XG5cdFx0aWYgKCFoYXMocmF3RGlyZWN0aXZlcywgcmF3RGlyZWN0aXZlTmFtZSkpIHtcblx0XHRcdGNvbnRpbnVlXG5cdFx0fVxuXHRcdGlmIChyYXdEaXJlY3RpdmVOYW1lLmxlbmd0aCA9PT0gMCB8fCAvW15hLXpBLVowLTktXS8udGVzdChyYXdEaXJlY3RpdmVOYW1lKSkge1xuXHRcdFx0dGhyb3cgbmV3IEVycm9yKGBDb250ZW50LVNlY3VyaXR5LVBvbGljeSByZWNlaXZlZCBhbiBpbnZhbGlkIGRpcmVjdGl2ZSBuYW1lICR7SlNPTi5zdHJpbmdpZnkocmF3RGlyZWN0aXZlTmFtZSl9YClcblx0XHR9XG5cdFx0Y29uc3QgZGlyZWN0aXZlTmFtZSA9IGRhc2hpZnkocmF3RGlyZWN0aXZlTmFtZSlcblx0XHRpZiAoZGlyZWN0aXZlTmFtZXNTZWVuLmhhcyhkaXJlY3RpdmVOYW1lKSkge1xuXHRcdFx0dGhyb3cgbmV3IEVycm9yKGBDb250ZW50LVNlY3VyaXR5LVBvbGljeSByZWNlaXZlZCBhIGR1cGxpY2F0ZSBkaXJlY3RpdmUgJHtKU09OLnN0cmluZ2lmeShkaXJlY3RpdmVOYW1lKX1gKVxuXHRcdH1cblx0XHRkaXJlY3RpdmVOYW1lc1NlZW4uYWRkKGRpcmVjdGl2ZU5hbWUpXG5cdFx0Y29uc3QgcmF3RGlyZWN0aXZlVmFsdWUgPSByYXdEaXJlY3RpdmVzW3Jhd0RpcmVjdGl2ZU5hbWVdXG5cdFx0bGV0IGRpcmVjdGl2ZVZhbHVlXG5cdFx0aWYgKHJhd0RpcmVjdGl2ZVZhbHVlID09PSBudWxsKSB7XG5cdFx0XHRpZiAoZGlyZWN0aXZlTmFtZSA9PT0gXCJkZWZhdWx0LXNyY1wiKSB7XG5cdFx0XHRcdHRocm93IG5ldyBFcnJvcihcIkNvbnRlbnQtU2VjdXJpdHktUG9saWN5IG5lZWRzIGEgZGVmYXVsdC1zcmMgYnV0IGl0IHdhcyBzZXQgdG8gYG51bGxgLiBJZiB5b3UgcmVhbGx5IHdhbnQgdG8gZGlzYWJsZSBpdCwgc2V0IGl0IHRvIGBjb250ZW50U2VjdXJpdHlQb2xpY3kuZGFuZ2Vyb3VzbHlEaXNhYmxlRGVmYXVsdFNyY2AuXCIpXG5cdFx0XHR9XG5cdFx0XHRkaXJlY3RpdmVzRXhwbGljaXRseURpc2FibGVkLmFkZChkaXJlY3RpdmVOYW1lKVxuXHRcdFx0Y29udGludWVcblx0XHR9IGVsc2UgaWYgKHR5cGVvZiByYXdEaXJlY3RpdmVWYWx1ZSA9PT0gXCJzdHJpbmdcIikge1xuXHRcdFx0ZGlyZWN0aXZlVmFsdWUgPSBbcmF3RGlyZWN0aXZlVmFsdWVdXG5cdFx0fSBlbHNlIGlmICghcmF3RGlyZWN0aXZlVmFsdWUpIHtcblx0XHRcdHRocm93IG5ldyBFcnJvcihgQ29udGVudC1TZWN1cml0eS1Qb2xpY3kgcmVjZWl2ZWQgYW4gaW52YWxpZCBkaXJlY3RpdmUgdmFsdWUgZm9yICR7SlNPTi5zdHJpbmdpZnkoZGlyZWN0aXZlTmFtZSl9YClcblx0XHR9IGVsc2UgaWYgKHJhd0RpcmVjdGl2ZVZhbHVlID09PSBkYW5nZXJvdXNseURpc2FibGVEZWZhdWx0U3JjKSB7XG5cdFx0XHRpZiAoZGlyZWN0aXZlTmFtZSA9PT0gXCJkZWZhdWx0LXNyY1wiKSB7XG5cdFx0XHRcdGRpcmVjdGl2ZXNFeHBsaWNpdGx5RGlzYWJsZWQuYWRkKFwiZGVmYXVsdC1zcmNcIilcblx0XHRcdFx0Y29udGludWVcblx0XHRcdH0gZWxzZSB7XG5cdFx0XHRcdHRocm93IG5ldyBFcnJvcihgQ29udGVudC1TZWN1cml0eS1Qb2xpY3k6IHRyaWVkIHRvIGRpc2FibGUgJHtKU09OLnN0cmluZ2lmeShkaXJlY3RpdmVOYW1lKX0gYXMgaWYgaXQgd2VyZSBkZWZhdWx0LXNyYzsgc2ltcGx5IG9taXQgdGhlIGtleWApXG5cdFx0XHR9XG5cdFx0fSBlbHNlIHtcblx0XHRcdGRpcmVjdGl2ZVZhbHVlID0gcmF3RGlyZWN0aXZlVmFsdWVcblx0XHR9XG5cdFx0Zm9yIChjb25zdCBlbGVtZW50IG9mIGRpcmVjdGl2ZVZhbHVlKSB7XG5cdFx0XHRpZiAodHlwZW9mIGVsZW1lbnQgPT09IFwic3RyaW5nXCIgJiYgaXNEaXJlY3RpdmVWYWx1ZUludmFsaWQoZWxlbWVudCkpIHtcblx0XHRcdFx0dGhyb3cgbmV3IEVycm9yKGBDb250ZW50LVNlY3VyaXR5LVBvbGljeSByZWNlaXZlZCBhbiBpbnZhbGlkIGRpcmVjdGl2ZSB2YWx1ZSBmb3IgJHtKU09OLnN0cmluZ2lmeShkaXJlY3RpdmVOYW1lKX1gKVxuXHRcdFx0fVxuXHRcdH1cblx0XHRyZXN1bHQuc2V0KGRpcmVjdGl2ZU5hbWUsIGRpcmVjdGl2ZVZhbHVlKVxuXHR9XG5cdGlmICh1c2VEZWZhdWx0cykge1xuXHRcdE9iamVjdC5lbnRyaWVzKGRlZmF1bHREaXJlY3RpdmVzKS5mb3JFYWNoKChbZGVmYXVsdERpcmVjdGl2ZU5hbWUsIGRlZmF1bHREaXJlY3RpdmVWYWx1ZV0pID0+IHtcblx0XHRcdGlmICghcmVzdWx0LmhhcyhkZWZhdWx0RGlyZWN0aXZlTmFtZSkgJiYgIWRpcmVjdGl2ZXNFeHBsaWNpdGx5RGlzYWJsZWQuaGFzKGRlZmF1bHREaXJlY3RpdmVOYW1lKSkge1xuXHRcdFx0XHRyZXN1bHQuc2V0KGRlZmF1bHREaXJlY3RpdmVOYW1lLCBkZWZhdWx0RGlyZWN0aXZlVmFsdWUpXG5cdFx0XHR9XG5cdFx0fSlcblx0fVxuXHRpZiAoIXJlc3VsdC5zaXplKSB7XG5cdFx0dGhyb3cgbmV3IEVycm9yKFwiQ29udGVudC1TZWN1cml0eS1Qb2xpY3kgaGFzIG5vIGRpcmVjdGl2ZXMuIEVpdGhlciBzZXQgc29tZSBvciBkaXNhYmxlIHRoZSBoZWFkZXJcIilcblx0fVxuXHRpZiAoIXJlc3VsdC5oYXMoXCJkZWZhdWx0LXNyY1wiKSAmJiAhZGlyZWN0aXZlc0V4cGxpY2l0bHlEaXNhYmxlZC5oYXMoXCJkZWZhdWx0LXNyY1wiKSkge1xuXHRcdHRocm93IG5ldyBFcnJvcihcIkNvbnRlbnQtU2VjdXJpdHktUG9saWN5IG5lZWRzIGEgZGVmYXVsdC1zcmMgYnV0IG5vbmUgd2FzIHByb3ZpZGVkLiBJZiB5b3UgcmVhbGx5IHdhbnQgdG8gZGlzYWJsZSBpdCwgc2V0IGl0IHRvIGBjb250ZW50U2VjdXJpdHlQb2xpY3kuZGFuZ2Vyb3VzbHlEaXNhYmxlRGVmYXVsdFNyY2AuXCIpXG5cdH1cblx0cmV0dXJuIHJlc3VsdFxufVxuZnVuY3Rpb24gZ2V0SGVhZGVyVmFsdWUocmVxLCByZXMsIG5vcm1hbGl6ZWREaXJlY3RpdmVzKSB7XG5cdGxldCBlcnJcblx0Y29uc3QgcmVzdWx0ID0gW11cblx0bm9ybWFsaXplZERpcmVjdGl2ZXMuZm9yRWFjaCgocmF3RGlyZWN0aXZlVmFsdWUsIGRpcmVjdGl2ZU5hbWUpID0+IHtcblx0XHRsZXQgZGlyZWN0aXZlVmFsdWUgPSBcIlwiXG5cdFx0Zm9yIChjb25zdCBlbGVtZW50IG9mIHJhd0RpcmVjdGl2ZVZhbHVlKSB7XG5cdFx0XHRkaXJlY3RpdmVWYWx1ZSArPSBcIiBcIiArIChlbGVtZW50IGluc3RhbmNlb2YgRnVuY3Rpb24gPyBlbGVtZW50KHJlcSwgcmVzKSA6IGVsZW1lbnQpXG5cdFx0fVxuXHRcdGlmICghZGlyZWN0aXZlVmFsdWUpIHtcblx0XHRcdHJlc3VsdC5wdXNoKGRpcmVjdGl2ZU5hbWUpXG5cdFx0fSBlbHNlIGlmIChpc0RpcmVjdGl2ZVZhbHVlSW52YWxpZChkaXJlY3RpdmVWYWx1ZSkpIHtcblx0XHRcdGVyciA9IG5ldyBFcnJvcihgQ29udGVudC1TZWN1cml0eS1Qb2xpY3kgcmVjZWl2ZWQgYW4gaW52YWxpZCBkaXJlY3RpdmUgdmFsdWUgZm9yICR7SlNPTi5zdHJpbmdpZnkoZGlyZWN0aXZlTmFtZSl9YClcblx0XHR9IGVsc2Uge1xuXHRcdFx0cmVzdWx0LnB1c2goYCR7ZGlyZWN0aXZlTmFtZX0ke2RpcmVjdGl2ZVZhbHVlfWApXG5cdFx0fVxuXHR9KVxuXHRyZXR1cm4gZXJyID8gZXJyIDogcmVzdWx0LmpvaW4oXCI7XCIpXG59XG5jb25zdCBjb250ZW50U2VjdXJpdHlQb2xpY3kgPSBmdW5jdGlvbiBjb250ZW50U2VjdXJpdHlQb2xpY3kob3B0aW9ucyA9IHt9KSB7XG5cdGNvbnN0IGhlYWRlck5hbWUgPSBvcHRpb25zLnJlcG9ydE9ubHkgPyBcIkNvbnRlbnQtU2VjdXJpdHktUG9saWN5LVJlcG9ydC1Pbmx5XCIgOiBcIkNvbnRlbnQtU2VjdXJpdHktUG9saWN5XCJcblx0Y29uc3Qgbm9ybWFsaXplZERpcmVjdGl2ZXMgPSBub3JtYWxpemVEaXJlY3RpdmVzKG9wdGlvbnMpXG5cdHJldHVybiBmdW5jdGlvbiBjb250ZW50U2VjdXJpdHlQb2xpY3lNaWRkbGV3YXJlKHJlcSwgcmVzLCBuZXh0KSB7XG5cdFx0Y29uc3QgcmVzdWx0ID0gZ2V0SGVhZGVyVmFsdWUocmVxLCByZXMsIG5vcm1hbGl6ZWREaXJlY3RpdmVzKVxuXHRcdGlmIChyZXN1bHQgaW5zdGFuY2VvZiBFcnJvcikge1xuXHRcdFx0bmV4dChyZXN1bHQpXG5cdFx0fSBlbHNlIHtcblx0XHRcdHJlcy5zZXRIZWFkZXIoaGVhZGVyTmFtZSwgcmVzdWx0KVxuXHRcdFx0bmV4dCgpXG5cdFx0fVxuXHR9XG59XG5jb250ZW50U2VjdXJpdHlQb2xpY3kuZ2V0RGVmYXVsdERpcmVjdGl2ZXMgPSBnZXREZWZhdWx0RGlyZWN0aXZlc1xuY29udGVudFNlY3VyaXR5UG9saWN5LmRhbmdlcm91c2x5RGlzYWJsZURlZmF1bHRTcmMgPSBkYW5nZXJvdXNseURpc2FibGVEZWZhdWx0U3JjXG5cbmNvbnN0IEFMTE9XRURfUE9MSUNJRVMkMiA9IG5ldyBTZXQoW1wicmVxdWlyZS1jb3JwXCIsIFwiY3JlZGVudGlhbGxlc3NcIl0pXG5mdW5jdGlvbiBnZXRIZWFkZXJWYWx1ZUZyb21PcHRpb25zJDcoe3BvbGljeSA9IFwicmVxdWlyZS1jb3JwXCJ9KSB7XG5cdGlmIChBTExPV0VEX1BPTElDSUVTJDIuaGFzKHBvbGljeSkpIHtcblx0XHRyZXR1cm4gcG9saWN5XG5cdH0gZWxzZSB7XG5cdFx0dGhyb3cgbmV3IEVycm9yKGBDcm9zcy1PcmlnaW4tRW1iZWRkZXItUG9saWN5IGRvZXMgbm90IHN1cHBvcnQgdGhlICR7SlNPTi5zdHJpbmdpZnkocG9saWN5KX0gcG9saWN5YClcblx0fVxufVxuZnVuY3Rpb24gY3Jvc3NPcmlnaW5FbWJlZGRlclBvbGljeShvcHRpb25zID0ge30pIHtcblx0Y29uc3QgaGVhZGVyVmFsdWUgPSBnZXRIZWFkZXJWYWx1ZUZyb21PcHRpb25zJDcob3B0aW9ucylcblx0cmV0dXJuIGZ1bmN0aW9uIGNyb3NzT3JpZ2luRW1iZWRkZXJQb2xpY3lNaWRkbGV3YXJlKF9yZXEsIHJlcywgbmV4dCkge1xuXHRcdHJlcy5zZXRIZWFkZXIoXCJDcm9zcy1PcmlnaW4tRW1iZWRkZXItUG9saWN5XCIsIGhlYWRlclZhbHVlKVxuXHRcdG5leHQoKVxuXHR9XG59XG5cbmNvbnN0IEFMTE9XRURfUE9MSUNJRVMkMSA9IG5ldyBTZXQoW1wic2FtZS1vcmlnaW5cIiwgXCJzYW1lLW9yaWdpbi1hbGxvdy1wb3B1cHNcIiwgXCJ1bnNhZmUtbm9uZVwiXSlcbmZ1bmN0aW9uIGdldEhlYWRlclZhbHVlRnJvbU9wdGlvbnMkNih7cG9saWN5ID0gXCJzYW1lLW9yaWdpblwifSkge1xuXHRpZiAoQUxMT1dFRF9QT0xJQ0lFUyQxLmhhcyhwb2xpY3kpKSB7XG5cdFx0cmV0dXJuIHBvbGljeVxuXHR9IGVsc2Uge1xuXHRcdHRocm93IG5ldyBFcnJvcihgQ3Jvc3MtT3JpZ2luLU9wZW5lci1Qb2xpY3kgZG9lcyBub3Qgc3VwcG9ydCB0aGUgJHtKU09OLnN0cmluZ2lmeShwb2xpY3kpfSBwb2xpY3lgKVxuXHR9XG59XG5mdW5jdGlvbiBjcm9zc09yaWdpbk9wZW5lclBvbGljeShvcHRpb25zID0ge30pIHtcblx0Y29uc3QgaGVhZGVyVmFsdWUgPSBnZXRIZWFkZXJWYWx1ZUZyb21PcHRpb25zJDYob3B0aW9ucylcblx0cmV0dXJuIGZ1bmN0aW9uIGNyb3NzT3JpZ2luT3BlbmVyUG9saWN5TWlkZGxld2FyZShfcmVxLCByZXMsIG5leHQpIHtcblx0XHRyZXMuc2V0SGVhZGVyKFwiQ3Jvc3MtT3JpZ2luLU9wZW5lci1Qb2xpY3lcIiwgaGVhZGVyVmFsdWUpXG5cdFx0bmV4dCgpXG5cdH1cbn1cblxuY29uc3QgQUxMT1dFRF9QT0xJQ0lFUyA9IG5ldyBTZXQoW1wic2FtZS1vcmlnaW5cIiwgXCJzYW1lLXNpdGVcIiwgXCJjcm9zcy1vcmlnaW5cIl0pXG5mdW5jdGlvbiBnZXRIZWFkZXJWYWx1ZUZyb21PcHRpb25zJDUoe3BvbGljeSA9IFwic2FtZS1vcmlnaW5cIn0pIHtcblx0aWYgKEFMTE9XRURfUE9MSUNJRVMuaGFzKHBvbGljeSkpIHtcblx0XHRyZXR1cm4gcG9saWN5XG5cdH0gZWxzZSB7XG5cdFx0dGhyb3cgbmV3IEVycm9yKGBDcm9zcy1PcmlnaW4tUmVzb3VyY2UtUG9saWN5IGRvZXMgbm90IHN1cHBvcnQgdGhlICR7SlNPTi5zdHJpbmdpZnkocG9saWN5KX0gcG9saWN5YClcblx0fVxufVxuZnVuY3Rpb24gY3Jvc3NPcmlnaW5SZXNvdXJjZVBvbGljeShvcHRpb25zID0ge30pIHtcblx0Y29uc3QgaGVhZGVyVmFsdWUgPSBnZXRIZWFkZXJWYWx1ZUZyb21PcHRpb25zJDUob3B0aW9ucylcblx0cmV0dXJuIGZ1bmN0aW9uIGNyb3NzT3JpZ2luUmVzb3VyY2VQb2xpY3lNaWRkbGV3YXJlKF9yZXEsIHJlcywgbmV4dCkge1xuXHRcdHJlcy5zZXRIZWFkZXIoXCJDcm9zcy1PcmlnaW4tUmVzb3VyY2UtUG9saWN5XCIsIGhlYWRlclZhbHVlKVxuXHRcdG5leHQoKVxuXHR9XG59XG5cbmZ1bmN0aW9uIHBhcnNlTWF4QWdlJDEodmFsdWUgPSAwKSB7XG5cdGlmICh2YWx1ZSA+PSAwICYmIE51bWJlci5pc0Zpbml0ZSh2YWx1ZSkpIHtcblx0XHRyZXR1cm4gTWF0aC5mbG9vcih2YWx1ZSlcblx0fSBlbHNlIHtcblx0XHR0aHJvdyBuZXcgRXJyb3IoYEV4cGVjdC1DVDogJHtKU09OLnN0cmluZ2lmeSh2YWx1ZSl9IGlzIG5vdCBhIHZhbGlkIHZhbHVlIGZvciBtYXhBZ2UuIFBsZWFzZSBjaG9vc2UgYSBwb3NpdGl2ZSBpbnRlZ2VyLmApXG5cdH1cbn1cbmZ1bmN0aW9uIGdldEhlYWRlclZhbHVlRnJvbU9wdGlvbnMkNChvcHRpb25zKSB7XG5cdGNvbnN0IGRpcmVjdGl2ZXMgPSBbYG1heC1hZ2U9JHtwYXJzZU1heEFnZSQxKG9wdGlvbnMubWF4QWdlKX1gXVxuXHRpZiAob3B0aW9ucy5lbmZvcmNlKSB7XG5cdFx0ZGlyZWN0aXZlcy5wdXNoKFwiZW5mb3JjZVwiKVxuXHR9XG5cdGlmIChvcHRpb25zLnJlcG9ydFVyaSkge1xuXHRcdGRpcmVjdGl2ZXMucHVzaChgcmVwb3J0LXVyaT1cIiR7b3B0aW9ucy5yZXBvcnRVcml9XCJgKVxuXHR9XG5cdHJldHVybiBkaXJlY3RpdmVzLmpvaW4oXCIsIFwiKVxufVxuZnVuY3Rpb24gZXhwZWN0Q3Qob3B0aW9ucyA9IHt9KSB7XG5cdGNvbnN0IGhlYWRlclZhbHVlID0gZ2V0SGVhZGVyVmFsdWVGcm9tT3B0aW9ucyQ0KG9wdGlvbnMpXG5cdHJldHVybiBmdW5jdGlvbiBleHBlY3RDdE1pZGRsZXdhcmUoX3JlcSwgcmVzLCBuZXh0KSB7XG5cdFx0cmVzLnNldEhlYWRlcihcIkV4cGVjdC1DVFwiLCBoZWFkZXJWYWx1ZSlcblx0XHRuZXh0KClcblx0fVxufVxuXG5mdW5jdGlvbiBvcmlnaW5BZ2VudENsdXN0ZXIoKSB7XG5cdHJldHVybiBmdW5jdGlvbiBvcmlnaW5BZ2VudENsdXN0ZXJNaWRkbGV3YXJlKF9yZXEsIHJlcywgbmV4dCkge1xuXHRcdHJlcy5zZXRIZWFkZXIoXCJPcmlnaW4tQWdlbnQtQ2x1c3RlclwiLCBcIj8xXCIpXG5cdFx0bmV4dCgpXG5cdH1cbn1cblxuY29uc3QgQUxMT1dFRF9UT0tFTlMgPSBuZXcgU2V0KFtcIm5vLXJlZmVycmVyXCIsIFwibm8tcmVmZXJyZXItd2hlbi1kb3duZ3JhZGVcIiwgXCJzYW1lLW9yaWdpblwiLCBcIm9yaWdpblwiLCBcInN0cmljdC1vcmlnaW5cIiwgXCJvcmlnaW4td2hlbi1jcm9zcy1vcmlnaW5cIiwgXCJzdHJpY3Qtb3JpZ2luLXdoZW4tY3Jvc3Mtb3JpZ2luXCIsIFwidW5zYWZlLXVybFwiLCBcIlwiXSlcbmZ1bmN0aW9uIGdldEhlYWRlclZhbHVlRnJvbU9wdGlvbnMkMyh7cG9saWN5ID0gW1wibm8tcmVmZXJyZXJcIl19KSB7XG5cdGNvbnN0IHRva2VucyA9IHR5cGVvZiBwb2xpY3kgPT09IFwic3RyaW5nXCIgPyBbcG9saWN5XSA6IHBvbGljeVxuXHRpZiAodG9rZW5zLmxlbmd0aCA9PT0gMCkge1xuXHRcdHRocm93IG5ldyBFcnJvcihcIlJlZmVycmVyLVBvbGljeSByZWNlaXZlZCBubyBwb2xpY3kgdG9rZW5zXCIpXG5cdH1cblx0Y29uc3QgdG9rZW5zU2VlbiA9IG5ldyBTZXQoKVxuXHR0b2tlbnMuZm9yRWFjaCh0b2tlbiA9PiB7XG5cdFx0aWYgKCFBTExPV0VEX1RPS0VOUy5oYXModG9rZW4pKSB7XG5cdFx0XHR0aHJvdyBuZXcgRXJyb3IoYFJlZmVycmVyLVBvbGljeSByZWNlaXZlZCBhbiB1bmV4cGVjdGVkIHBvbGljeSB0b2tlbiAke0pTT04uc3RyaW5naWZ5KHRva2VuKX1gKVxuXHRcdH0gZWxzZSBpZiAodG9rZW5zU2Vlbi5oYXModG9rZW4pKSB7XG5cdFx0XHR0aHJvdyBuZXcgRXJyb3IoYFJlZmVycmVyLVBvbGljeSByZWNlaXZlZCBhIGR1cGxpY2F0ZSBwb2xpY3kgdG9rZW4gJHtKU09OLnN0cmluZ2lmeSh0b2tlbil9YClcblx0XHR9XG5cdFx0dG9rZW5zU2Vlbi5hZGQodG9rZW4pXG5cdH0pXG5cdHJldHVybiB0b2tlbnMuam9pbihcIixcIilcbn1cbmZ1bmN0aW9uIHJlZmVycmVyUG9saWN5KG9wdGlvbnMgPSB7fSkge1xuXHRjb25zdCBoZWFkZXJWYWx1ZSA9IGdldEhlYWRlclZhbHVlRnJvbU9wdGlvbnMkMyhvcHRpb25zKVxuXHRyZXR1cm4gZnVuY3Rpb24gcmVmZXJyZXJQb2xpY3lNaWRkbGV3YXJlKF9yZXEsIHJlcywgbmV4dCkge1xuXHRcdHJlcy5zZXRIZWFkZXIoXCJSZWZlcnJlci1Qb2xpY3lcIiwgaGVhZGVyVmFsdWUpXG5cdFx0bmV4dCgpXG5cdH1cbn1cblxuY29uc3QgREVGQVVMVF9NQVhfQUdFID0gMTgwICogMjQgKiA2MCAqIDYwXG5mdW5jdGlvbiBwYXJzZU1heEFnZSh2YWx1ZSA9IERFRkFVTFRfTUFYX0FHRSkge1xuXHRpZiAodmFsdWUgPj0gMCAmJiBOdW1iZXIuaXNGaW5pdGUodmFsdWUpKSB7XG5cdFx0cmV0dXJuIE1hdGguZmxvb3IodmFsdWUpXG5cdH0gZWxzZSB7XG5cdFx0dGhyb3cgbmV3IEVycm9yKGBTdHJpY3QtVHJhbnNwb3J0LVNlY3VyaXR5OiAke0pTT04uc3RyaW5naWZ5KHZhbHVlKX0gaXMgbm90IGEgdmFsaWQgdmFsdWUgZm9yIG1heEFnZS4gUGxlYXNlIGNob29zZSBhIHBvc2l0aXZlIGludGVnZXIuYClcblx0fVxufVxuZnVuY3Rpb24gZ2V0SGVhZGVyVmFsdWVGcm9tT3B0aW9ucyQyKG9wdGlvbnMpIHtcblx0aWYgKFwibWF4YWdlXCIgaW4gb3B0aW9ucykge1xuXHRcdHRocm93IG5ldyBFcnJvcihcIlN0cmljdC1UcmFuc3BvcnQtU2VjdXJpdHkgcmVjZWl2ZWQgYW4gdW5zdXBwb3J0ZWQgcHJvcGVydHksIGBtYXhhZ2VgLiBEaWQgeW91IG1lYW4gdG8gcGFzcyBgbWF4QWdlYD9cIilcblx0fVxuXHRpZiAoXCJpbmNsdWRlU3ViZG9tYWluc1wiIGluIG9wdGlvbnMpIHtcblx0XHRjb25zb2xlLndhcm4oJ1N0cmljdC1UcmFuc3BvcnQtU2VjdXJpdHkgbWlkZGxld2FyZSBzaG91bGQgdXNlIGBpbmNsdWRlU3ViRG9tYWluc2AgaW5zdGVhZCBvZiBgaW5jbHVkZVN1YmRvbWFpbnNgLiAoVGhlIGNvcnJlY3Qgb25lIGhhcyBhbiB1cHBlcmNhc2UgXCJEXCIuKScpXG5cdH1cblx0aWYgKFwic2V0SWZcIiBpbiBvcHRpb25zKSB7XG5cdFx0Y29uc29sZS53YXJuKFwiU3RyaWN0LVRyYW5zcG9ydC1TZWN1cml0eSBtaWRkbGV3YXJlIG5vIGxvbmdlciBzdXBwb3J0cyB0aGUgYHNldElmYCBwYXJhbWV0ZXIuIFNlZSB0aGUgZG9jdW1lbnRhdGlvbiBhbmQgPGh0dHBzOi8vZ2l0aHViLmNvbS9oZWxtZXRqcy9oZWxtZXQvd2lraS9Db25kaXRpb25hbGx5LXVzaW5nLW1pZGRsZXdhcmU+IGlmIHlvdSBuZWVkIGhlbHAgcmVwbGljYXRpbmcgdGhpcyBiZWhhdmlvci5cIilcblx0fVxuXHRjb25zdCBkaXJlY3RpdmVzID0gW2BtYXgtYWdlPSR7cGFyc2VNYXhBZ2Uob3B0aW9ucy5tYXhBZ2UpfWBdXG5cdGlmIChvcHRpb25zLmluY2x1ZGVTdWJEb21haW5zID09PSB1bmRlZmluZWQgfHwgb3B0aW9ucy5pbmNsdWRlU3ViRG9tYWlucykge1xuXHRcdGRpcmVjdGl2ZXMucHVzaChcImluY2x1ZGVTdWJEb21haW5zXCIpXG5cdH1cblx0aWYgKG9wdGlvbnMucHJlbG9hZCkge1xuXHRcdGRpcmVjdGl2ZXMucHVzaChcInByZWxvYWRcIilcblx0fVxuXHRyZXR1cm4gZGlyZWN0aXZlcy5qb2luKFwiOyBcIilcbn1cbmZ1bmN0aW9uIHN0cmljdFRyYW5zcG9ydFNlY3VyaXR5KG9wdGlvbnMgPSB7fSkge1xuXHRjb25zdCBoZWFkZXJWYWx1ZSA9IGdldEhlYWRlclZhbHVlRnJvbU9wdGlvbnMkMihvcHRpb25zKVxuXHRyZXR1cm4gZnVuY3Rpb24gc3RyaWN0VHJhbnNwb3J0U2VjdXJpdHlNaWRkbGV3YXJlKF9yZXEsIHJlcywgbmV4dCkge1xuXHRcdHJlcy5zZXRIZWFkZXIoXCJTdHJpY3QtVHJhbnNwb3J0LVNlY3VyaXR5XCIsIGhlYWRlclZhbHVlKVxuXHRcdG5leHQoKVxuXHR9XG59XG5cbmZ1bmN0aW9uIHhDb250ZW50VHlwZU9wdGlvbnMoKSB7XG5cdHJldHVybiBmdW5jdGlvbiB4Q29udGVudFR5cGVPcHRpb25zTWlkZGxld2FyZShfcmVxLCByZXMsIG5leHQpIHtcblx0XHRyZXMuc2V0SGVhZGVyKFwiWC1Db250ZW50LVR5cGUtT3B0aW9uc1wiLCBcIm5vc25pZmZcIilcblx0XHRuZXh0KClcblx0fVxufVxuXG5mdW5jdGlvbiB4RG5zUHJlZmV0Y2hDb250cm9sKG9wdGlvbnMgPSB7fSkge1xuXHRjb25zdCBoZWFkZXJWYWx1ZSA9IG9wdGlvbnMuYWxsb3cgPyBcIm9uXCIgOiBcIm9mZlwiXG5cdHJldHVybiBmdW5jdGlvbiB4RG5zUHJlZmV0Y2hDb250cm9sTWlkZGxld2FyZShfcmVxLCByZXMsIG5leHQpIHtcblx0XHRyZXMuc2V0SGVhZGVyKFwiWC1ETlMtUHJlZmV0Y2gtQ29udHJvbFwiLCBoZWFkZXJWYWx1ZSlcblx0XHRuZXh0KClcblx0fVxufVxuXG5mdW5jdGlvbiB4RG93bmxvYWRPcHRpb25zKCkge1xuXHRyZXR1cm4gZnVuY3Rpb24geERvd25sb2FkT3B0aW9uc01pZGRsZXdhcmUoX3JlcSwgcmVzLCBuZXh0KSB7XG5cdFx0cmVzLnNldEhlYWRlcihcIlgtRG93bmxvYWQtT3B0aW9uc1wiLCBcIm5vb3BlblwiKVxuXHRcdG5leHQoKVxuXHR9XG59XG5cbmZ1bmN0aW9uIGdldEhlYWRlclZhbHVlRnJvbU9wdGlvbnMkMSh7YWN0aW9uID0gXCJzYW1lb3JpZ2luXCJ9KSB7XG5cdGNvbnN0IG5vcm1hbGl6ZWRBY3Rpb24gPSB0eXBlb2YgYWN0aW9uID09PSBcInN0cmluZ1wiID8gYWN0aW9uLnRvVXBwZXJDYXNlKCkgOiBhY3Rpb25cblx0c3dpdGNoIChub3JtYWxpemVkQWN0aW9uKSB7XG5cdFx0Y2FzZSBcIlNBTUUtT1JJR0lOXCI6XG5cdFx0XHRyZXR1cm4gXCJTQU1FT1JJR0lOXCJcblx0XHRjYXNlIFwiREVOWVwiOlxuXHRcdGNhc2UgXCJTQU1FT1JJR0lOXCI6XG5cdFx0XHRyZXR1cm4gbm9ybWFsaXplZEFjdGlvblxuXHRcdGRlZmF1bHQ6XG5cdFx0XHR0aHJvdyBuZXcgRXJyb3IoYFgtRnJhbWUtT3B0aW9ucyByZWNlaXZlZCBhbiBpbnZhbGlkIGFjdGlvbiAke0pTT04uc3RyaW5naWZ5KGFjdGlvbil9YClcblx0fVxufVxuZnVuY3Rpb24geEZyYW1lT3B0aW9ucyhvcHRpb25zID0ge30pIHtcblx0Y29uc3QgaGVhZGVyVmFsdWUgPSBnZXRIZWFkZXJWYWx1ZUZyb21PcHRpb25zJDEob3B0aW9ucylcblx0cmV0dXJuIGZ1bmN0aW9uIHhGcmFtZU9wdGlvbnNNaWRkbGV3YXJlKF9yZXEsIHJlcywgbmV4dCkge1xuXHRcdHJlcy5zZXRIZWFkZXIoXCJYLUZyYW1lLU9wdGlvbnNcIiwgaGVhZGVyVmFsdWUpXG5cdFx0bmV4dCgpXG5cdH1cbn1cblxuY29uc3QgQUxMT1dFRF9QRVJNSVRURURfUE9MSUNJRVMgPSBuZXcgU2V0KFtcIm5vbmVcIiwgXCJtYXN0ZXItb25seVwiLCBcImJ5LWNvbnRlbnQtdHlwZVwiLCBcImFsbFwiXSlcbmZ1bmN0aW9uIGdldEhlYWRlclZhbHVlRnJvbU9wdGlvbnMoe3Blcm1pdHRlZFBvbGljaWVzID0gXCJub25lXCJ9KSB7XG5cdGlmIChBTExPV0VEX1BFUk1JVFRFRF9QT0xJQ0lFUy5oYXMocGVybWl0dGVkUG9saWNpZXMpKSB7XG5cdFx0cmV0dXJuIHBlcm1pdHRlZFBvbGljaWVzXG5cdH0gZWxzZSB7XG5cdFx0dGhyb3cgbmV3IEVycm9yKGBYLVBlcm1pdHRlZC1Dcm9zcy1Eb21haW4tUG9saWNpZXMgZG9lcyBub3Qgc3VwcG9ydCAke0pTT04uc3RyaW5naWZ5KHBlcm1pdHRlZFBvbGljaWVzKX1gKVxuXHR9XG59XG5mdW5jdGlvbiB4UGVybWl0dGVkQ3Jvc3NEb21haW5Qb2xpY2llcyhvcHRpb25zID0ge30pIHtcblx0Y29uc3QgaGVhZGVyVmFsdWUgPSBnZXRIZWFkZXJWYWx1ZUZyb21PcHRpb25zKG9wdGlvbnMpXG5cdHJldHVybiBmdW5jdGlvbiB4UGVybWl0dGVkQ3Jvc3NEb21haW5Qb2xpY2llc01pZGRsZXdhcmUoX3JlcSwgcmVzLCBuZXh0KSB7XG5cdFx0cmVzLnNldEhlYWRlcihcIlgtUGVybWl0dGVkLUNyb3NzLURvbWFpbi1Qb2xpY2llc1wiLCBoZWFkZXJWYWx1ZSlcblx0XHRuZXh0KClcblx0fVxufVxuXG5mdW5jdGlvbiB4UG93ZXJlZEJ5KCkge1xuXHRyZXR1cm4gZnVuY3Rpb24geFBvd2VyZWRCeU1pZGRsZXdhcmUoX3JlcSwgcmVzLCBuZXh0KSB7XG5cdFx0cmVzLnJlbW92ZUhlYWRlcihcIlgtUG93ZXJlZC1CeVwiKVxuXHRcdG5leHQoKVxuXHR9XG59XG5cbmZ1bmN0aW9uIHhYc3NQcm90ZWN0aW9uKCkge1xuXHRyZXR1cm4gZnVuY3Rpb24geFhzc1Byb3RlY3Rpb25NaWRkbGV3YXJlKF9yZXEsIHJlcywgbmV4dCkge1xuXHRcdHJlcy5zZXRIZWFkZXIoXCJYLVhTUy1Qcm90ZWN0aW9uXCIsIFwiMFwiKVxuXHRcdG5leHQoKVxuXHR9XG59XG5cbmZ1bmN0aW9uIGdldEFyZ3Mob3B0aW9uLCBtaWRkbGV3YXJlQ29uZmlnID0ge30pIHtcblx0c3dpdGNoIChvcHRpb24pIHtcblx0XHRjYXNlIHVuZGVmaW5lZDpcblx0XHRjYXNlIHRydWU6XG5cdFx0XHRyZXR1cm4gW11cblx0XHRjYXNlIGZhbHNlOlxuXHRcdFx0cmV0dXJuIG51bGxcblx0XHRkZWZhdWx0OlxuXHRcdFx0aWYgKG1pZGRsZXdhcmVDb25maWcudGFrZXNPcHRpb25zID09PSBmYWxzZSkge1xuXHRcdFx0XHRjb25zb2xlLndhcm4oYCR7bWlkZGxld2FyZUNvbmZpZy5uYW1lfSBkb2VzIG5vdCB0YWtlIG9wdGlvbnMuIFJlbW92ZSB0aGUgcHJvcGVydHkgdG8gc2lsZW5jZSB0aGlzIHdhcm5pbmcuYClcblx0XHRcdFx0cmV0dXJuIFtdXG5cdFx0XHR9IGVsc2Uge1xuXHRcdFx0XHRyZXR1cm4gW29wdGlvbl1cblx0XHRcdH1cblx0fVxufVxuZnVuY3Rpb24gZ2V0TWlkZGxld2FyZUZ1bmN0aW9uc0Zyb21PcHRpb25zKG9wdGlvbnMpIHtcblx0Y29uc3QgcmVzdWx0ID0gW11cblx0Y29uc3QgY29udGVudFNlY3VyaXR5UG9saWN5QXJncyA9IGdldEFyZ3Mob3B0aW9ucy5jb250ZW50U2VjdXJpdHlQb2xpY3kpXG5cdGlmIChjb250ZW50U2VjdXJpdHlQb2xpY3lBcmdzKSB7XG5cdFx0cmVzdWx0LnB1c2goY29udGVudFNlY3VyaXR5UG9saWN5KC4uLmNvbnRlbnRTZWN1cml0eVBvbGljeUFyZ3MpKVxuXHR9XG5cdGNvbnN0IGNyb3NzT3JpZ2luRW1iZWRkZXJQb2xpY3lBcmdzID0gZ2V0QXJncyhvcHRpb25zLmNyb3NzT3JpZ2luRW1iZWRkZXJQb2xpY3kpXG5cdGlmIChjcm9zc09yaWdpbkVtYmVkZGVyUG9saWN5QXJncykge1xuXHRcdHJlc3VsdC5wdXNoKGNyb3NzT3JpZ2luRW1iZWRkZXJQb2xpY3koLi4uY3Jvc3NPcmlnaW5FbWJlZGRlclBvbGljeUFyZ3MpKVxuXHR9XG5cdGNvbnN0IGNyb3NzT3JpZ2luT3BlbmVyUG9saWN5QXJncyA9IGdldEFyZ3Mob3B0aW9ucy5jcm9zc09yaWdpbk9wZW5lclBvbGljeSlcblx0aWYgKGNyb3NzT3JpZ2luT3BlbmVyUG9saWN5QXJncykge1xuXHRcdHJlc3VsdC5wdXNoKGNyb3NzT3JpZ2luT3BlbmVyUG9saWN5KC4uLmNyb3NzT3JpZ2luT3BlbmVyUG9saWN5QXJncykpXG5cdH1cblx0Y29uc3QgY3Jvc3NPcmlnaW5SZXNvdXJjZVBvbGljeUFyZ3MgPSBnZXRBcmdzKG9wdGlvbnMuY3Jvc3NPcmlnaW5SZXNvdXJjZVBvbGljeSlcblx0aWYgKGNyb3NzT3JpZ2luUmVzb3VyY2VQb2xpY3lBcmdzKSB7XG5cdFx0cmVzdWx0LnB1c2goY3Jvc3NPcmlnaW5SZXNvdXJjZVBvbGljeSguLi5jcm9zc09yaWdpblJlc291cmNlUG9saWN5QXJncykpXG5cdH1cblx0Y29uc3QgeERuc1ByZWZldGNoQ29udHJvbEFyZ3MgPSBnZXRBcmdzKG9wdGlvbnMuZG5zUHJlZmV0Y2hDb250cm9sKVxuXHRpZiAoeERuc1ByZWZldGNoQ29udHJvbEFyZ3MpIHtcblx0XHRyZXN1bHQucHVzaCh4RG5zUHJlZmV0Y2hDb250cm9sKC4uLnhEbnNQcmVmZXRjaENvbnRyb2xBcmdzKSlcblx0fVxuXHRjb25zdCBleHBlY3RDdEFyZ3MgPSBvcHRpb25zLmV4cGVjdEN0ICYmIGdldEFyZ3Mob3B0aW9ucy5leHBlY3RDdClcblx0aWYgKGV4cGVjdEN0QXJncykge1xuXHRcdHJlc3VsdC5wdXNoKGV4cGVjdEN0KC4uLmV4cGVjdEN0QXJncykpXG5cdH1cblx0Y29uc3QgeEZyYW1lT3B0aW9uc0FyZ3MgPSBnZXRBcmdzKG9wdGlvbnMuZnJhbWVndWFyZClcblx0aWYgKHhGcmFtZU9wdGlvbnNBcmdzKSB7XG5cdFx0cmVzdWx0LnB1c2goeEZyYW1lT3B0aW9ucyguLi54RnJhbWVPcHRpb25zQXJncykpXG5cdH1cblx0Y29uc3QgeFBvd2VyZWRCeUFyZ3MgPSBnZXRBcmdzKG9wdGlvbnMuaGlkZVBvd2VyZWRCeSwge1xuXHRcdG5hbWU6IFwiaGlkZVBvd2VyZWRCeVwiLFxuXHRcdHRha2VzT3B0aW9uczogZmFsc2Vcblx0fSlcblx0aWYgKHhQb3dlcmVkQnlBcmdzKSB7XG5cdFx0cmVzdWx0LnB1c2goeFBvd2VyZWRCeSgpKVxuXHR9XG5cdGNvbnN0IHN0cmljdFRyYW5zcG9ydFNlY3VyaXR5QXJncyA9IGdldEFyZ3Mob3B0aW9ucy5oc3RzKVxuXHRpZiAoc3RyaWN0VHJhbnNwb3J0U2VjdXJpdHlBcmdzKSB7XG5cdFx0cmVzdWx0LnB1c2goc3RyaWN0VHJhbnNwb3J0U2VjdXJpdHkoLi4uc3RyaWN0VHJhbnNwb3J0U2VjdXJpdHlBcmdzKSlcblx0fVxuXHRjb25zdCB4RG93bmxvYWRPcHRpb25zQXJncyA9IGdldEFyZ3Mob3B0aW9ucy5pZU5vT3Blbiwge1xuXHRcdG5hbWU6IFwiaWVOb09wZW5cIixcblx0XHR0YWtlc09wdGlvbnM6IGZhbHNlXG5cdH0pXG5cdGlmICh4RG93bmxvYWRPcHRpb25zQXJncykge1xuXHRcdHJlc3VsdC5wdXNoKHhEb3dubG9hZE9wdGlvbnMoKSlcblx0fVxuXHRjb25zdCB4Q29udGVudFR5cGVPcHRpb25zQXJncyA9IGdldEFyZ3Mob3B0aW9ucy5ub1NuaWZmLCB7XG5cdFx0bmFtZTogXCJub1NuaWZmXCIsXG5cdFx0dGFrZXNPcHRpb25zOiBmYWxzZVxuXHR9KVxuXHRpZiAoeENvbnRlbnRUeXBlT3B0aW9uc0FyZ3MpIHtcblx0XHRyZXN1bHQucHVzaCh4Q29udGVudFR5cGVPcHRpb25zKCkpXG5cdH1cblx0Y29uc3Qgb3JpZ2luQWdlbnRDbHVzdGVyQXJncyA9IGdldEFyZ3Mob3B0aW9ucy5vcmlnaW5BZ2VudENsdXN0ZXIsIHtcblx0XHRuYW1lOiBcIm9yaWdpbkFnZW50Q2x1c3RlclwiLFxuXHRcdHRha2VzT3B0aW9uczogZmFsc2Vcblx0fSlcblx0aWYgKG9yaWdpbkFnZW50Q2x1c3RlckFyZ3MpIHtcblx0XHRyZXN1bHQucHVzaChvcmlnaW5BZ2VudENsdXN0ZXIoKSlcblx0fVxuXHRjb25zdCB4UGVybWl0dGVkQ3Jvc3NEb21haW5Qb2xpY2llc0FyZ3MgPSBnZXRBcmdzKG9wdGlvbnMucGVybWl0dGVkQ3Jvc3NEb21haW5Qb2xpY2llcylcblx0aWYgKHhQZXJtaXR0ZWRDcm9zc0RvbWFpblBvbGljaWVzQXJncykge1xuXHRcdHJlc3VsdC5wdXNoKHhQZXJtaXR0ZWRDcm9zc0RvbWFpblBvbGljaWVzKC4uLnhQZXJtaXR0ZWRDcm9zc0RvbWFpblBvbGljaWVzQXJncykpXG5cdH1cblx0Y29uc3QgcmVmZXJyZXJQb2xpY3lBcmdzID0gZ2V0QXJncyhvcHRpb25zLnJlZmVycmVyUG9saWN5KVxuXHRpZiAocmVmZXJyZXJQb2xpY3lBcmdzKSB7XG5cdFx0cmVzdWx0LnB1c2gocmVmZXJyZXJQb2xpY3koLi4ucmVmZXJyZXJQb2xpY3lBcmdzKSlcblx0fVxuXHRjb25zdCB4WHNzUHJvdGVjdGlvbkFyZ3MgPSBnZXRBcmdzKG9wdGlvbnMueHNzRmlsdGVyLCB7XG5cdFx0bmFtZTogXCJ4c3NGaWx0ZXJcIixcblx0XHR0YWtlc09wdGlvbnM6IGZhbHNlXG5cdH0pXG5cdGlmICh4WHNzUHJvdGVjdGlvbkFyZ3MpIHtcblx0XHRyZXN1bHQucHVzaCh4WHNzUHJvdGVjdGlvbigpKVxuXHR9XG5cdHJldHVybiByZXN1bHRcbn1cbmNvbnN0IGhlbG1ldCA9IE9iamVjdC5hc3NpZ24oXG5cdGZ1bmN0aW9uIGhlbG1ldChvcHRpb25zID0ge30pIHtcblx0XHR2YXIgX2Fcblx0XHQvLyBQZW9wbGUgc2hvdWxkIGJlIGFibGUgdG8gcGFzcyBhbiBvcHRpb25zIG9iamVjdCB3aXRoIG5vIHByb3RvdHlwZSxcblx0XHQvLyBzbyB3ZSB3YW50IHRoaXMgb3B0aW9uYWwgY2hhaW5pbmcuXG5cdFx0Ly8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIEB0eXBlc2NyaXB0LWVzbGludC9uby11bm5lY2Vzc2FyeS1jb25kaXRpb25cblx0XHRpZiAoKChfYSA9IG9wdGlvbnMuY29uc3RydWN0b3IpID09PSBudWxsIHx8IF9hID09PSB2b2lkIDAgPyB2b2lkIDAgOiBfYS5uYW1lKSA9PT0gXCJJbmNvbWluZ01lc3NhZ2VcIikge1xuXHRcdFx0dGhyb3cgbmV3IEVycm9yKFwiSXQgYXBwZWFycyB5b3UgaGF2ZSBkb25lIHNvbWV0aGluZyBsaWtlIGBhcHAudXNlKGhlbG1ldClgLCBidXQgaXQgc2hvdWxkIGJlIGBhcHAudXNlKGhlbG1ldCgpKWAuXCIpXG5cdFx0fVxuXHRcdGNvbnN0IG1pZGRsZXdhcmVGdW5jdGlvbnMgPSBnZXRNaWRkbGV3YXJlRnVuY3Rpb25zRnJvbU9wdGlvbnMob3B0aW9ucylcblx0XHRyZXR1cm4gZnVuY3Rpb24gaGVsbWV0TWlkZGxld2FyZShyZXEsIHJlcywgbmV4dCkge1xuXHRcdFx0bGV0IG1pZGRsZXdhcmVJbmRleCA9IDBcblx0XHRcdDsoZnVuY3Rpb24gaW50ZXJuYWxOZXh0KGVycikge1xuXHRcdFx0XHRpZiAoZXJyKSB7XG5cdFx0XHRcdFx0bmV4dChlcnIpXG5cdFx0XHRcdFx0cmV0dXJuXG5cdFx0XHRcdH1cblx0XHRcdFx0Y29uc3QgbWlkZGxld2FyZUZ1bmN0aW9uID0gbWlkZGxld2FyZUZ1bmN0aW9uc1ttaWRkbGV3YXJlSW5kZXhdXG5cdFx0XHRcdGlmIChtaWRkbGV3YXJlRnVuY3Rpb24pIHtcblx0XHRcdFx0XHRtaWRkbGV3YXJlSW5kZXgrK1xuXHRcdFx0XHRcdG1pZGRsZXdhcmVGdW5jdGlvbihyZXEsIHJlcywgaW50ZXJuYWxOZXh0KVxuXHRcdFx0XHR9IGVsc2Uge1xuXHRcdFx0XHRcdG5leHQoKVxuXHRcdFx0XHR9XG5cdFx0XHR9KSgpXG5cdFx0fVxuXHR9LFxuXHR7XG5cdFx0Y29udGVudFNlY3VyaXR5UG9saWN5LFxuXHRcdGNyb3NzT3JpZ2luRW1iZWRkZXJQb2xpY3ksXG5cdFx0Y3Jvc3NPcmlnaW5PcGVuZXJQb2xpY3ksXG5cdFx0Y3Jvc3NPcmlnaW5SZXNvdXJjZVBvbGljeSxcblx0XHRkbnNQcmVmZXRjaENvbnRyb2w6IHhEbnNQcmVmZXRjaENvbnRyb2wsXG5cdFx0ZXhwZWN0Q3QsXG5cdFx0ZnJhbWVndWFyZDogeEZyYW1lT3B0aW9ucyxcblx0XHRoaWRlUG93ZXJlZEJ5OiB4UG93ZXJlZEJ5LFxuXHRcdGhzdHM6IHN0cmljdFRyYW5zcG9ydFNlY3VyaXR5LFxuXHRcdGllTm9PcGVuOiB4RG93bmxvYWRPcHRpb25zLFxuXHRcdG5vU25pZmY6IHhDb250ZW50VHlwZU9wdGlvbnMsXG5cdFx0b3JpZ2luQWdlbnRDbHVzdGVyLFxuXHRcdHBlcm1pdHRlZENyb3NzRG9tYWluUG9saWNpZXM6IHhQZXJtaXR0ZWRDcm9zc0RvbWFpblBvbGljaWVzLFxuXHRcdHJlZmVycmVyUG9saWN5LFxuXHRcdHhzc0ZpbHRlcjogeFhzc1Byb3RlY3Rpb25cblx0fVxuKVxuXG5leHBvcnQge2NvbnRlbnRTZWN1cml0eVBvbGljeSwgY3Jvc3NPcmlnaW5FbWJlZGRlclBvbGljeSwgY3Jvc3NPcmlnaW5PcGVuZXJQb2xpY3ksIGNyb3NzT3JpZ2luUmVzb3VyY2VQb2xpY3ksIGhlbG1ldCBhcyBkZWZhdWx0LCB4RG5zUHJlZmV0Y2hDb250cm9sIGFzIGRuc1ByZWZldGNoQ29udHJvbCwgZXhwZWN0Q3QsIHhGcmFtZU9wdGlvbnMgYXMgZnJhbWVndWFyZCwgeFBvd2VyZWRCeSBhcyBoaWRlUG93ZXJlZEJ5LCBzdHJpY3RUcmFuc3BvcnRTZWN1cml0eSBhcyBoc3RzLCB4RG93bmxvYWRPcHRpb25zIGFzIGllTm9PcGVuLCB4Q29udGVudFR5cGVPcHRpb25zIGFzIG5vU25pZmYsIG9yaWdpbkFnZW50Q2x1c3RlciwgeFBlcm1pdHRlZENyb3NzRG9tYWluUG9saWNpZXMgYXMgcGVybWl0dGVkQ3Jvc3NEb21haW5Qb2xpY2llcywgcmVmZXJyZXJQb2xpY3ksIHhYc3NQcm90ZWN0aW9uIGFzIHhzc0ZpbHRlcn1cbiIsImltcG9ydCB7IFNjaGVtYSwgbW9kZWwsIG1vZGVscyB9IGZyb20gJ21vbmdvb3NlJztcbmNvbnN0IExhYlNjaGVtYSA9IG5ldyBTY2hlbWEoe1xuICAgIG5hbWU6IHtcbiAgICAgICAgdHlwZTogU3RyaW5nLFxuICAgICAgICByZXF1aXJlZDogdHJ1ZSxcbiAgICB9LFxufSk7XG5jb25zdCBEaXNjaXBsaW5lU2NoZW1hID0gbmV3IFNjaGVtYSh7XG4gICAgbmFtZToge1xuICAgICAgICB0eXBlOiBTdHJpbmcsXG4gICAgICAgIHJlcXVpcmVkOiB0cnVlLFxuICAgIH0sXG4gICAgdGVhY2hlcnM6IHtcbiAgICAgICAgdHlwZTogU3RyaW5nLFxuICAgICAgICByZXF1aXJlZDogdHJ1ZSxcbiAgICB9LFxuICAgIHRlYWNoZXJFbWFpbDoge1xuICAgICAgICB0eXBlOiBTdHJpbmcsXG4gICAgICAgIHJlcXVpcmVkOiB0cnVlLFxuICAgIH0sXG4gICAgbGFiczoge1xuICAgICAgICB0eXBlOiBbTGFiU2NoZW1hXSxcbiAgICAgICAgcmVxdWlyZWQ6IHRydWUsXG4gICAgfSxcbn0pO1xuY29uc3QgU3BlY2lhbGl0aWVTY2hlbWEgPSBuZXcgU2NoZW1hKHtcbiAgICBpZDoge1xuICAgICAgICB0eXBlOiBTdHJpbmcsXG4gICAgICAgIHJlcXVpcmVkOiB0cnVlLFxuICAgIH0sXG4gICAgbmFtZToge1xuICAgICAgICB0eXBlOiBTdHJpbmcsXG4gICAgICAgIHJlcXVpcmVkOiB0cnVlLFxuICAgIH0sXG4gICAgZGlzY2lwbGluZXM6IHtcbiAgICAgICAgdHlwZTogW0Rpc2NpcGxpbmVTY2hlbWFdLFxuICAgICAgICByZXF1aXJlZDogdHJ1ZSxcbiAgICB9LFxufSk7XG5jb25zdCBVbml2ZXJzaXR5U2NoZW1hID0gbmV3IFNjaGVtYSh7XG4gICAgX2lkOiB7XG4gICAgICAgIHR5cGU6IE51bWJlcixcbiAgICAgICAgcmVxdWlyZWQ6IHRydWUsXG4gICAgfSxcbiAgICBpZDoge1xuICAgICAgICB0eXBlOiBTdHJpbmcsXG4gICAgICAgIHJlcXVpcmVkOiB0cnVlLFxuICAgIH0sXG4gICAgbmFtZToge1xuICAgICAgICB0eXBlOiBTdHJpbmcsXG4gICAgICAgIHJlcXVpcmVkOiB0cnVlLFxuICAgIH0sXG4gICAgYWJicjoge1xuICAgICAgICB0eXBlOiBTdHJpbmcsXG4gICAgICAgIHJlcXVpcmVkOiB0cnVlLFxuICAgIH0sXG4gICAgc3BlY2lhbGl0aWVzOiB7XG4gICAgICAgIHR5cGU6IFtTcGVjaWFsaXRpZVNjaGVtYV0sXG4gICAgICAgIHJlcXVpcmVkOiB0cnVlLFxuICAgIH0sXG59KTtcbmV4cG9ydCBjb25zdCBVbml2ZXJzaXR5TW9kZWwgPSBtb2RlbHMuVW5pdmVyc2l0eSA/PyBtb2RlbCgnVW5pdmVyc2l0eScsIFVuaXZlcnNpdHlTY2hlbWEpO1xuIiwiaW1wb3J0IHsgVW5pdmVyc2l0eU1vZGVsIH0gZnJvbSAnQC9EYXRhYmFzZS9tb2RlbHMnO1xuZXhwb3J0IGNvbnN0IGdldCA9IGFzeW5jIChyZXEsIHJlcykgPT4ge1xuICAgIHRyeSB7XG4gICAgICAgIGNvbnN0IGRhdGEgPSBhd2FpdCBVbml2ZXJzaXR5TW9kZWwuZmluZCgpLmxlYW4oKTtcbiAgICAgICAgcmV0dXJuIHJlcy5zZW5kKGRhdGEpO1xuICAgIH1cbiAgICBjYXRjaCAoZXJyb3IpIHtcbiAgICAgICAgcmV0dXJuIHJlcy5zZW5kKCk7XG4gICAgfVxuICAgIGZpbmFsbHkge1xuICAgICAgICByZXMuZW5kKCk7XG4gICAgfVxufTtcbiIsImltcG9ydCB7IFJvdXRlciB9IGZyb20gJ2V4cHJlc3MnO1xuaW1wb3J0IHsgZ2V0IH0gZnJvbSAnQC9hcGkvY29udHJvbGxlcnMvdW5pdmVyc2l0eSc7XG5jb25zdCB1bml2ZXJzaXR5Um91dGVyID0gUm91dGVyKCk7XG51bml2ZXJzaXR5Um91dGVyLmdldCgnLycsIGdldCk7XG5leHBvcnQgeyB1bml2ZXJzaXR5Um91dGVyIH07XG4iLCJpbXBvcnQgeyBSb3V0ZXIgfSBmcm9tICdleHByZXNzJztcbmltcG9ydCB7IHVuaXZlcnNpdHlSb3V0ZXIgfSBmcm9tICcuL3JvdXRlcyc7XG5jb25zdCBhcGlSb3V0ZXIgPSBSb3V0ZXIoKTtcbmFwaVJvdXRlci51c2UoJy91bml2ZXJzaXR5JywgdW5pdmVyc2l0eVJvdXRlcik7XG5leHBvcnQgeyBhcGlSb3V0ZXIgfTtcbiIsImltcG9ydCBib2R5UGFyc2VyIGZyb20gJ2JvZHktcGFyc2VyJztcbmltcG9ydCBjb21wcmVzc2lvbiBmcm9tICdjb21wcmVzc2lvbic7XG5pbXBvcnQgY29ycyBmcm9tICdjb3JzJztcbmltcG9ydCBleHByZXNzIGZyb20gJ2V4cHJlc3MnO1xuaW1wb3J0IGhlbG1ldCBmcm9tICdoZWxtZXQnO1xuaW1wb3J0IHsgYXBpUm91dGVyIH0gZnJvbSAnQC9hcGknO1xuY29uc3Qgc2VydmVyID0gZXhwcmVzcygpO1xudHJ5IHtcbiAgICBzZXJ2ZXIudXNlKGJvZHlQYXJzZXIudXJsZW5jb2RlZCh7IGV4dGVuZGVkOiB0cnVlIH0pKTtcbiAgICBzZXJ2ZXIudXNlKGJvZHlQYXJzZXIuanNvbigpKTtcbiAgICBzZXJ2ZXIudXNlKGNvbXByZXNzaW9uKCkpO1xuICAgIHNlcnZlci51c2UoY29ycygpKTtcbiAgICBzZXJ2ZXIudXNlKGhlbG1ldCh7XG4gICAgICAgIGNvbnRlbnRTZWN1cml0eVBvbGljeTogZmFsc2UsXG4gICAgfSkpO1xuICAgIHNlcnZlci51c2UoJy9hcGknLCBhcGlSb3V0ZXIpO1xuICAgIGNvbnNvbGUubG9nKCdbU0VSVkVSXSBJbml0aWFsaXplZCcpO1xufVxuY2F0Y2ggKGVycm9yKSB7XG4gICAgY29uc29sZS5lcnJvcihlcnJvcik7XG59XG5leHBvcnQgeyBzZXJ2ZXIgfTtcbiIsImltcG9ydCB7IGNvbmZpZyB9IGZyb20gJ2RvdGVudic7XG5jb25maWcoKTtcbi8vIGdsb2JhbFxuZXhwb3J0IGNvbnN0IFBPUlQgPSBwcm9jZXNzLmVudi5QT1JUID8/IDQwMDA7XG4vLyBkYXRhYmFzZVxuLy8gZGF0YWJhc2VcbmV4cG9ydCBjb25zdCBEQl9VU0VSID0gcHJvY2Vzcy5lbnYuREJfVVNFUjtcbmV4cG9ydCBjb25zdCBEQl9QQVNTID0gcHJvY2Vzcy5lbnYuREJfUEFTUztcbmV4cG9ydCBjb25zdCBEQl9OQU1FID0gcHJvY2Vzcy5lbnYuREJfTkFNRTtcbmV4cG9ydCBjb25zdCBEQl9DT05OU1RSID0gcHJvY2Vzcy5lbnYuREJfQ09OTlNUUlxuICAgIC5yZXBsYWNlKCc8dXNlcj4nLCBEQl9VU0VSKVxuICAgIC5yZXBsYWNlKCc8cGFzcz4nLCBEQl9QQVNTKVxuICAgIC5yZXBsYWNlKCc8ZGI+JywgREJfTkFNRSk7XG4iLCJpbXBvcnQgeyBjb25uZWN0LCBjb25uZWN0aW9uLCBzZXQgfSBmcm9tICdtb25nb29zZSc7XG5pbXBvcnQgeyBEQl9DT05OU1RSLCBEQl9OQU1FIH0gZnJvbSAnQC9jb25maWcnO1xuc2V0KCdzdHJpY3RRdWVyeScsIGZhbHNlKTtcbmNsYXNzIERhdGFiYXNlIHtcbiAgICBzdGF0aWMgaW5zdGFuY2UgPSBudWxsO1xuICAgIGNvbnN0cnVjdG9yKCkge1xuICAgICAgICBpZiAoRGF0YWJhc2UuaW5zdGFuY2UgPT09IG51bGwpXG4gICAgICAgICAgICBEYXRhYmFzZS5pbnN0YW5jZSA9IHRoaXM7XG4gICAgICAgIHJldHVybiBEYXRhYmFzZS5pbnN0YW5jZTtcbiAgICB9XG4gICAgaXNDb25uZWN0ZWQgPSAoKSA9PiBjb25uZWN0aW9uLnJlYWR5U3RhdGUgPT09IDE7XG4gICAgY29ubmVjdCA9IGFzeW5jICgpID0+IHtcbiAgICAgICAgY29uc3QgZGVmYXVsdFJldHVybiA9IHRoaXMuaXNDb25uZWN0ZWQ7XG4gICAgICAgIGlmICh0aGlzLmlzQ29ubmVjdGVkKCkpXG4gICAgICAgICAgICByZXR1cm4gZGVmYXVsdFJldHVybjtcbiAgICAgICAgY29uc29sZS5sb2coJ1tEQl0gQ29ubmVjdGluZy4uLicpO1xuICAgICAgICB0cnkge1xuICAgICAgICAgICAgYXdhaXQgY29ubmVjdChEQl9DT05OU1RSKTtcbiAgICAgICAgICAgIGNvbnNvbGUubG9nKGBbREJdIENvbm5lY3RlZCB0byBcIiR7REJfTkFNRX1cImApO1xuICAgICAgICB9XG4gICAgICAgIGNhdGNoIChlcnJvcikge1xuICAgICAgICAgICAgY29uc29sZS5lcnJvcignW0RCXSBDb25uZWN0aW9uIGVycm9yJyk7XG4gICAgICAgICAgICBjb25zb2xlLmVycm9yKGVycm9yKTtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gZGVmYXVsdFJldHVybjtcbiAgICB9O1xufVxuZXhwb3J0IHsgRGF0YWJhc2UgfTtcbiIsImNvbnN0IGxvY2FsZSA9ICd1ay1VQSc7XG5jb25zdCB0aW1lWm9uZSA9ICdFdXJvcGUvS2lldic7XG5leHBvcnQgY29uc3QgZ2V0Q3VycmVudFRpbWVTdHJpbmcgPSAoKSA9PiBuZXcgRGF0ZSgpLnRvTG9jYWxlVGltZVN0cmluZyhsb2NhbGUsIHtcbiAgICB0aW1lWm9uZSxcbiAgICBob3VyOiAnMi1kaWdpdCcsXG4gICAgbWludXRlOiAnMi1kaWdpdCcsXG4gICAgc2Vjb25kOiAnMi1kaWdpdCcsXG59KTtcbmV4cG9ydCBjb25zdCBnZXRDdXJyZW50RGF0ZVN0cmluZyA9ICgpID0+IG5ldyBEYXRlKCkudG9Mb2NhbGVEYXRlU3RyaW5nKGxvY2FsZSwge1xuICAgIHRpbWVab25lLFxuICAgIHdlZWtkYXk6ICdsb25nJyxcbiAgICB5ZWFyOiAnbnVtZXJpYycsXG4gICAgbW9udGg6ICdsb25nJyxcbiAgICBkYXk6ICdudW1lcmljJyxcbiAgICBob3VyOiAnbnVtZXJpYycsXG4gICAgbWludXRlOiAnbnVtZXJpYycsXG59KTtcbiIsImltcG9ydCB7IFBPUlQgfSBmcm9tICdAL2NvbmZpZyc7XG5pbXBvcnQgeyBnZXRDdXJyZW50VGltZVN0cmluZyB9IGZyb20gJ0AvdXRpbHMnO1xuZXhwb3J0IGNvbnN0IG1haW5MaXN0ZW4gPSAoKSA9PiB7XG4gICAgdHJ5IHtcbiAgICAgICAgY29uc29sZS5sb2coYFtTRVJWRVJdIHwgJHtnZXRDdXJyZW50VGltZVN0cmluZygpfSBMaXN0ZW5pbmcgYXQgJHtQT1JUfWApO1xuICAgIH1cbiAgICBjYXRjaCAoZXJyb3IpIHtcbiAgICAgICAgY29uc29sZS5lcnJvcihlcnJvcik7XG4gICAgfVxufTtcbiIsImltcG9ydCB7IHNlcnZlciB9IGZyb20gJy4vc2VydmVyJztcbmltcG9ydCB7IERhdGFiYXNlIH0gZnJvbSAnQC9EYXRhYmFzZSc7XG5pbXBvcnQgeyBtYWluTGlzdGVuIH0gZnJvbSAnQC9hcGkvY29udHJvbGxlcnMnO1xuaW1wb3J0IHsgUE9SVCB9IGZyb20gJ0AvY29uZmlnJztcbmNvbnN0IHN0YXJ0ID0gYXN5bmMgKCkgPT4ge1xuICAgIGNvbnN0IGRhdGFiYXNlID0gbmV3IERhdGFiYXNlKCk7XG4gICAgdm9pZCBzZXJ2ZXIubGlzdGVuKFBPUlQsIG1haW5MaXN0ZW4pO1xuICAgIHZvaWQgZGF0YWJhc2UuY29ubmVjdCgpO1xufTtcbnZvaWQgc3RhcnQoKTtcbiJdLCJuYW1lcyI6WyJTY2hlbWEiLCJtb2RlbHMiLCJtb2RlbCIsIlJvdXRlciIsImNvbmZpZyIsInNldCIsImNvbm5lY3Rpb24iLCJjb25uZWN0Il0sIm1hcHBpbmdzIjoiOzs7Ozs7Ozs7QUFBQSxNQUFNLDRCQUE0QixHQUFHLE1BQU0sQ0FBQyw4QkFBOEIsRUFBQztBQUMzRSxNQUFNLGtCQUFrQixHQUFHO0FBQzNCLENBQUMsYUFBYSxFQUFFLENBQUMsUUFBUSxDQUFDO0FBQzFCLENBQUMsVUFBVSxFQUFFLENBQUMsUUFBUSxDQUFDO0FBQ3ZCLENBQUMsVUFBVSxFQUFFLENBQUMsUUFBUSxFQUFFLFFBQVEsRUFBRSxPQUFPLENBQUM7QUFDMUMsQ0FBQyxhQUFhLEVBQUUsQ0FBQyxRQUFRLENBQUM7QUFDMUIsQ0FBQyxpQkFBaUIsRUFBRSxDQUFDLFFBQVEsQ0FBQztBQUM5QixDQUFDLFNBQVMsRUFBRSxDQUFDLFFBQVEsRUFBRSxP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
