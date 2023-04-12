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

// global
const INTERNAL_SERVER = 'Виникла помилка';

// 200
const OK = 200;
// 400
const BAD_REQUEST = 400;
// 500
const INTERNAL_SERVER_ERROR = 500;

class ApiError {
    status;
    message;
    error;
    constructor(params) {
        const { status, message, error } = params;
        this.status = status;
        this.message = message;
        this.error = error ?? '';
    }
    static internalServerError(error) {
        return new ApiError({
            status: INTERNAL_SERVER_ERROR,
            message: INTERNAL_SERVER,
            error,
        });
    }
    // TODO implement
    notify() { }
}

class ApiSuccess {
    status;
    message;
    data;
    constructor(params) {
        const { status, message, data } = params;
        this.status = status;
        this.message = message;
        this.data = data;
    }
}

const post = async (req, res) => {
    try {
        const { email, password } = req.body;
        if (email === undefined || password === undefined) {
            const response = new ApiError({
                status: BAD_REQUEST,
                message: 'Email or password is missing',
            });
            return res.status(response.status).send(response);
        }
        // const
    }
    catch (error) {
        const response = ApiError.internalServerError(error);
        return res.status(response.status).send(response);
    }
    finally {
        res.end();
    }
};

const loginRouter = express.Router();
loginRouter.get('/', post);

const LabSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
    },
    rating: {
        type: Number,
        required: true,
    },
    message: {
        type: String,
        required: true,
    },
});
const DisciplineSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
    },
    teacher: {
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
        const universities = await UniversityModel.find().lean();
        const data = universities.find((item) => item.abbr === 'LPNU');
        const response = new ApiSuccess({
            status: OK,
            message: 'Success',
            data,
        });
        return res.status(response.status).send(response);
    }
    catch (error) {
        const response = ApiError.internalServerError(error);
        return res.status(response.status).send(response);
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
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXguanMiLCJzb3VyY2VzIjpbIi4uL25vZGVfbW9kdWxlcy8ucG5wbS9oZWxtZXRANi4xLjUvbm9kZV9tb2R1bGVzL2hlbG1ldC9pbmRleC5tanMiLCIuLi9zcmMvYXBpL3Jlc3BvbnNlcy9lcnJvck1lc3NhZ2VzLnRzIiwiLi4vc3JjL2FwaS9yZXNwb25zZXMvc3RhdHVzQ29kZXMudHMiLCIuLi9zcmMvYXBpL3Jlc3BvbnNlcy9BcGlFcnJvci50cyIsIi4uL3NyYy9hcGkvcmVzcG9uc2VzL0FwaVN1Y2Nlc3MudHMiLCIuLi9zcmMvYXBpL2NvbnRyb2xsZXJzL2xvZ2luL3Bvc3QudHMiLCIuLi9zcmMvYXBpL3JvdXRlcy9sb2dpblJvdXRlci50cyIsIi4uL3NyYy9EYXRhYmFzZS9tb2RlbHMvVW5pdmVyc2l0eS50cyIsIi4uL3NyYy9hcGkvY29udHJvbGxlcnMvdW5pdmVyc2l0eS9nZXQudHMiLCIuLi9zcmMvYXBpL3JvdXRlcy91bml2ZXJzaXR5Um91dGVyLnRzIiwiLi4vc3JjL2FwaS9hcGlSb3V0ZXIudHMiLCIuLi9zcmMvc2VydmVyLnRzIiwiLi4vc3JjL2NvbmZpZy50cyIsIi4uL3NyYy9EYXRhYmFzZS9EYXRhYmFzZS50cyIsIi4uL3NyYy91dGlscy9kYXRlLnRzIiwiLi4vc3JjL2FwaS9jb250cm9sbGVycy9tYWluL21haW5MaXN0ZW4udHMiLCIuLi9zcmMvaW5kZXgudHMiXSwic291cmNlc0NvbnRlbnQiOlsiY29uc3QgZGFuZ2Vyb3VzbHlEaXNhYmxlRGVmYXVsdFNyYyA9IFN5bWJvbChcImRhbmdlcm91c2x5RGlzYWJsZURlZmF1bHRTcmNcIilcbmNvbnN0IERFRkFVTFRfRElSRUNUSVZFUyA9IHtcblx0XCJkZWZhdWx0LXNyY1wiOiBbXCInc2VsZidcIl0sXG5cdFwiYmFzZS11cmlcIjogW1wiJ3NlbGYnXCJdLFxuXHRcImZvbnQtc3JjXCI6IFtcIidzZWxmJ1wiLCBcImh0dHBzOlwiLCBcImRhdGE6XCJdLFxuXHRcImZvcm0tYWN0aW9uXCI6IFtcIidzZWxmJ1wiXSxcblx0XCJmcmFtZS1hbmNlc3RvcnNcIjogW1wiJ3NlbGYnXCJdLFxuXHRcImltZy1zcmNcIjogW1wiJ3NlbGYnXCIsIFwiZGF0YTpcIl0sXG5cdFwib2JqZWN0LXNyY1wiOiBbXCInbm9uZSdcIl0sXG5cdFwic2NyaXB0LXNyY1wiOiBbXCInc2VsZidcIl0sXG5cdFwic2NyaXB0LXNyYy1hdHRyXCI6IFtcIidub25lJ1wiXSxcblx0XCJzdHlsZS1zcmNcIjogW1wiJ3NlbGYnXCIsIFwiaHR0cHM6XCIsIFwiJ3Vuc2FmZS1pbmxpbmUnXCJdLFxuXHRcInVwZ3JhZGUtaW5zZWN1cmUtcmVxdWVzdHNcIjogW11cbn1cbmNvbnN0IGdldERlZmF1bHREaXJlY3RpdmVzID0gKCkgPT4gT2JqZWN0LmFzc2lnbih7fSwgREVGQVVMVF9ESVJFQ1RJVkVTKVxuY29uc3QgZGFzaGlmeSA9IHN0ciA9PiBzdHIucmVwbGFjZSgvW0EtWl0vZywgY2FwaXRhbExldHRlciA9PiBcIi1cIiArIGNhcGl0YWxMZXR0ZXIudG9Mb3dlckNhc2UoKSlcbmNvbnN0IGlzRGlyZWN0aXZlVmFsdWVJbnZhbGlkID0gZGlyZWN0aXZlVmFsdWUgPT4gLzt8LC8udGVzdChkaXJlY3RpdmVWYWx1ZSlcbmNvbnN0IGhhcyA9IChvYmosIGtleSkgPT4gT2JqZWN0LnByb3RvdHlwZS5oYXNPd25Qcm9wZXJ0eS5jYWxsKG9iaiwga2V5KVxuZnVuY3Rpb24gbm9ybWFsaXplRGlyZWN0aXZlcyhvcHRpb25zKSB7XG5cdGNvbnN0IGRlZmF1bHREaXJlY3RpdmVzID0gZ2V0RGVmYXVsdERpcmVjdGl2ZXMoKVxuXHRjb25zdCB7dXNlRGVmYXVsdHMgPSB0cnVlLCBkaXJlY3RpdmVzOiByYXdEaXJlY3RpdmVzID0gZGVmYXVsdERpcmVjdGl2ZXN9ID0gb3B0aW9uc1xuXHRjb25zdCByZXN1bHQgPSBuZXcgTWFwKClcblx0Y29uc3QgZGlyZWN0aXZlTmFtZXNTZWVuID0gbmV3IFNldCgpXG5cdGNvbnN0IGRpcmVjdGl2ZXNFeHBsaWNpdGx5RGlzYWJsZWQgPSBuZXcgU2V0KClcblx0Zm9yIChjb25zdCByYXdEaXJlY3RpdmVOYW1lIGluIHJhd0RpcmVjdGl2ZXMpIHtcblx0XHRpZiAoIWhhcyhyYXdEaXJlY3RpdmVzLCByYXdEaXJlY3RpdmVOYW1lKSkge1xuXHRcdFx0Y29udGludWVcblx0XHR9XG5cdFx0aWYgKHJhd0RpcmVjdGl2ZU5hbWUubGVuZ3RoID09PSAwIHx8IC9bXmEtekEtWjAtOS1dLy50ZXN0KHJhd0RpcmVjdGl2ZU5hbWUpKSB7XG5cdFx0XHR0aHJvdyBuZXcgRXJyb3IoYENvbnRlbnQtU2VjdXJpdHktUG9saWN5IHJlY2VpdmVkIGFuIGludmFsaWQgZGlyZWN0aXZlIG5hbWUgJHtKU09OLnN0cmluZ2lmeShyYXdEaXJlY3RpdmVOYW1lKX1gKVxuXHRcdH1cblx0XHRjb25zdCBkaXJlY3RpdmVOYW1lID0gZGFzaGlmeShyYXdEaXJlY3RpdmVOYW1lKVxuXHRcdGlmIChkaXJlY3RpdmVOYW1lc1NlZW4uaGFzKGRpcmVjdGl2ZU5hbWUpKSB7XG5cdFx0XHR0aHJvdyBuZXcgRXJyb3IoYENvbnRlbnQtU2VjdXJpdHktUG9saWN5IHJlY2VpdmVkIGEgZHVwbGljYXRlIGRpcmVjdGl2ZSAke0pTT04uc3RyaW5naWZ5KGRpcmVjdGl2ZU5hbWUpfWApXG5cdFx0fVxuXHRcdGRpcmVjdGl2ZU5hbWVzU2Vlbi5hZGQoZGlyZWN0aXZlTmFtZSlcblx0XHRjb25zdCByYXdEaXJlY3RpdmVWYWx1ZSA9IHJhd0RpcmVjdGl2ZXNbcmF3RGlyZWN0aXZlTmFtZV1cblx0XHRsZXQgZGlyZWN0aXZlVmFsdWVcblx0XHRpZiAocmF3RGlyZWN0aXZlVmFsdWUgPT09IG51bGwpIHtcblx0XHRcdGlmIChkaXJlY3RpdmVOYW1lID09PSBcImRlZmF1bHQtc3JjXCIpIHtcblx0XHRcdFx0dGhyb3cgbmV3IEVycm9yKFwiQ29udGVudC1TZWN1cml0eS1Qb2xpY3kgbmVlZHMgYSBkZWZhdWx0LXNyYyBidXQgaXQgd2FzIHNldCB0byBgbnVsbGAuIElmIHlvdSByZWFsbHkgd2FudCB0byBkaXNhYmxlIGl0LCBzZXQgaXQgdG8gYGNvbnRlbnRTZWN1cml0eVBvbGljeS5kYW5nZXJvdXNseURpc2FibGVEZWZhdWx0U3JjYC5cIilcblx0XHRcdH1cblx0XHRcdGRpcmVjdGl2ZXNFeHBsaWNpdGx5RGlzYWJsZWQuYWRkKGRpcmVjdGl2ZU5hbWUpXG5cdFx0XHRjb250aW51ZVxuXHRcdH0gZWxzZSBpZiAodHlwZW9mIHJhd0RpcmVjdGl2ZVZhbHVlID09PSBcInN0cmluZ1wiKSB7XG5cdFx0XHRkaXJlY3RpdmVWYWx1ZSA9IFtyYXdEaXJlY3RpdmVWYWx1ZV1cblx0XHR9IGVsc2UgaWYgKCFyYXdEaXJlY3RpdmVWYWx1ZSkge1xuXHRcdFx0dGhyb3cgbmV3IEVycm9yKGBDb250ZW50LVNlY3VyaXR5LVBvbGljeSByZWNlaXZlZCBhbiBpbnZhbGlkIGRpcmVjdGl2ZSB2YWx1ZSBmb3IgJHtKU09OLnN0cmluZ2lmeShkaXJlY3RpdmVOYW1lKX1gKVxuXHRcdH0gZWxzZSBpZiAocmF3RGlyZWN0aXZlVmFsdWUgPT09IGRhbmdlcm91c2x5RGlzYWJsZURlZmF1bHRTcmMpIHtcblx0XHRcdGlmIChkaXJlY3RpdmVOYW1lID09PSBcImRlZmF1bHQtc3JjXCIpIHtcblx0XHRcdFx0ZGlyZWN0aXZlc0V4cGxpY2l0bHlEaXNhYmxlZC5hZGQoXCJkZWZhdWx0LXNyY1wiKVxuXHRcdFx0XHRjb250aW51ZVxuXHRcdFx0fSBlbHNlIHtcblx0XHRcdFx0dGhyb3cgbmV3IEVycm9yKGBDb250ZW50LVNlY3VyaXR5LVBvbGljeTogdHJpZWQgdG8gZGlzYWJsZSAke0pTT04uc3RyaW5naWZ5KGRpcmVjdGl2ZU5hbWUpfSBhcyBpZiBpdCB3ZXJlIGRlZmF1bHQtc3JjOyBzaW1wbHkgb21pdCB0aGUga2V5YClcblx0XHRcdH1cblx0XHR9IGVsc2Uge1xuXHRcdFx0ZGlyZWN0aXZlVmFsdWUgPSByYXdEaXJlY3RpdmVWYWx1ZVxuXHRcdH1cblx0XHRmb3IgKGNvbnN0IGVsZW1lbnQgb2YgZGlyZWN0aXZlVmFsdWUpIHtcblx0XHRcdGlmICh0eXBlb2YgZWxlbWVudCA9PT0gXCJzdHJpbmdcIiAmJiBpc0RpcmVjdGl2ZVZhbHVlSW52YWxpZChlbGVtZW50KSkge1xuXHRcdFx0XHR0aHJvdyBuZXcgRXJyb3IoYENvbnRlbnQtU2VjdXJpdHktUG9saWN5IHJlY2VpdmVkIGFuIGludmFsaWQgZGlyZWN0aXZlIHZhbHVlIGZvciAke0pTT04uc3RyaW5naWZ5KGRpcmVjdGl2ZU5hbWUpfWApXG5cdFx0XHR9XG5cdFx0fVxuXHRcdHJlc3VsdC5zZXQoZGlyZWN0aXZlTmFtZSwgZGlyZWN0aXZlVmFsdWUpXG5cdH1cblx0aWYgKHVzZURlZmF1bHRzKSB7XG5cdFx0T2JqZWN0LmVudHJpZXMoZGVmYXVsdERpcmVjdGl2ZXMpLmZvckVhY2goKFtkZWZhdWx0RGlyZWN0aXZlTmFtZSwgZGVmYXVsdERpcmVjdGl2ZVZhbHVlXSkgPT4ge1xuXHRcdFx0aWYgKCFyZXN1bHQuaGFzKGRlZmF1bHREaXJlY3RpdmVOYW1lKSAmJiAhZGlyZWN0aXZlc0V4cGxpY2l0bHlEaXNhYmxlZC5oYXMoZGVmYXVsdERpcmVjdGl2ZU5hbWUpKSB7XG5cdFx0XHRcdHJlc3VsdC5zZXQoZGVmYXVsdERpcmVjdGl2ZU5hbWUsIGRlZmF1bHREaXJlY3RpdmVWYWx1ZSlcblx0XHRcdH1cblx0XHR9KVxuXHR9XG5cdGlmICghcmVzdWx0LnNpemUpIHtcblx0XHR0aHJvdyBuZXcgRXJyb3IoXCJDb250ZW50LVNlY3VyaXR5LVBvbGljeSBoYXMgbm8gZGlyZWN0aXZlcy4gRWl0aGVyIHNldCBzb21lIG9yIGRpc2FibGUgdGhlIGhlYWRlclwiKVxuXHR9XG5cdGlmICghcmVzdWx0LmhhcyhcImRlZmF1bHQtc3JjXCIpICYmICFkaXJlY3RpdmVzRXhwbGljaXRseURpc2FibGVkLmhhcyhcImRlZmF1bHQtc3JjXCIpKSB7XG5cdFx0dGhyb3cgbmV3IEVycm9yKFwiQ29udGVudC1TZWN1cml0eS1Qb2xpY3kgbmVlZHMgYSBkZWZhdWx0LXNyYyBidXQgbm9uZSB3YXMgcHJvdmlkZWQuIElmIHlvdSByZWFsbHkgd2FudCB0byBkaXNhYmxlIGl0LCBzZXQgaXQgdG8gYGNvbnRlbnRTZWN1cml0eVBvbGljeS5kYW5nZXJvdXNseURpc2FibGVEZWZhdWx0U3JjYC5cIilcblx0fVxuXHRyZXR1cm4gcmVzdWx0XG59XG5mdW5jdGlvbiBnZXRIZWFkZXJWYWx1ZShyZXEsIHJlcywgbm9ybWFsaXplZERpcmVjdGl2ZXMpIHtcblx0bGV0IGVyclxuXHRjb25zdCByZXN1bHQgPSBbXVxuXHRub3JtYWxpemVkRGlyZWN0aXZlcy5mb3JFYWNoKChyYXdEaXJlY3RpdmVWYWx1ZSwgZGlyZWN0aXZlTmFtZSkgPT4ge1xuXHRcdGxldCBkaXJlY3RpdmVWYWx1ZSA9IFwiXCJcblx0XHRmb3IgKGNvbnN0IGVsZW1lbnQgb2YgcmF3RGlyZWN0aXZlVmFsdWUpIHtcblx0XHRcdGRpcmVjdGl2ZVZhbHVlICs9IFwiIFwiICsgKGVsZW1lbnQgaW5zdGFuY2VvZiBGdW5jdGlvbiA/IGVsZW1lbnQocmVxLCByZXMpIDogZWxlbWVudClcblx0XHR9XG5cdFx0aWYgKCFkaXJlY3RpdmVWYWx1ZSkge1xuXHRcdFx0cmVzdWx0LnB1c2goZGlyZWN0aXZlTmFtZSlcblx0XHR9IGVsc2UgaWYgKGlzRGlyZWN0aXZlVmFsdWVJbnZhbGlkKGRpcmVjdGl2ZVZhbHVlKSkge1xuXHRcdFx0ZXJyID0gbmV3IEVycm9yKGBDb250ZW50LVNlY3VyaXR5LVBvbGljeSByZWNlaXZlZCBhbiBpbnZhbGlkIGRpcmVjdGl2ZSB2YWx1ZSBmb3IgJHtKU09OLnN0cmluZ2lmeShkaXJlY3RpdmVOYW1lKX1gKVxuXHRcdH0gZWxzZSB7XG5cdFx0XHRyZXN1bHQucHVzaChgJHtkaXJlY3RpdmVOYW1lfSR7ZGlyZWN0aXZlVmFsdWV9YClcblx0XHR9XG5cdH0pXG5cdHJldHVybiBlcnIgPyBlcnIgOiByZXN1bHQuam9pbihcIjtcIilcbn1cbmNvbnN0IGNvbnRlbnRTZWN1cml0eVBvbGljeSA9IGZ1bmN0aW9uIGNvbnRlbnRTZWN1cml0eVBvbGljeShvcHRpb25zID0ge30pIHtcblx0Y29uc3QgaGVhZGVyTmFtZSA9IG9wdGlvbnMucmVwb3J0T25seSA/IFwiQ29udGVudC1TZWN1cml0eS1Qb2xpY3ktUmVwb3J0LU9ubHlcIiA6IFwiQ29udGVudC1TZWN1cml0eS1Qb2xpY3lcIlxuXHRjb25zdCBub3JtYWxpemVkRGlyZWN0aXZlcyA9IG5vcm1hbGl6ZURpcmVjdGl2ZXMob3B0aW9ucylcblx0cmV0dXJuIGZ1bmN0aW9uIGNvbnRlbnRTZWN1cml0eVBvbGljeU1pZGRsZXdhcmUocmVxLCByZXMsIG5leHQpIHtcblx0XHRjb25zdCByZXN1bHQgPSBnZXRIZWFkZXJWYWx1ZShyZXEsIHJlcywgbm9ybWFsaXplZERpcmVjdGl2ZXMpXG5cdFx0aWYgKHJlc3VsdCBpbnN0YW5jZW9mIEVycm9yKSB7XG5cdFx0XHRuZXh0KHJlc3VsdClcblx0XHR9IGVsc2Uge1xuXHRcdFx0cmVzLnNldEhlYWRlcihoZWFkZXJOYW1lLCByZXN1bHQpXG5cdFx0XHRuZXh0KClcblx0XHR9XG5cdH1cbn1cbmNvbnRlbnRTZWN1cml0eVBvbGljeS5nZXREZWZhdWx0RGlyZWN0aXZlcyA9IGdldERlZmF1bHREaXJlY3RpdmVzXG5jb250ZW50U2VjdXJpdHlQb2xpY3kuZGFuZ2Vyb3VzbHlEaXNhYmxlRGVmYXVsdFNyYyA9IGRhbmdlcm91c2x5RGlzYWJsZURlZmF1bHRTcmNcblxuY29uc3QgQUxMT1dFRF9QT0xJQ0lFUyQyID0gbmV3IFNldChbXCJyZXF1aXJlLWNvcnBcIiwgXCJjcmVkZW50aWFsbGVzc1wiXSlcbmZ1bmN0aW9uIGdldEhlYWRlclZhbHVlRnJvbU9wdGlvbnMkNyh7cG9saWN5ID0gXCJyZXF1aXJlLWNvcnBcIn0pIHtcblx0aWYgKEFMTE9XRURfUE9MSUNJRVMkMi5oYXMocG9saWN5KSkge1xuXHRcdHJldHVybiBwb2xpY3lcblx0fSBlbHNlIHtcblx0XHR0aHJvdyBuZXcgRXJyb3IoYENyb3NzLU9yaWdpbi1FbWJlZGRlci1Qb2xpY3kgZG9lcyBub3Qgc3VwcG9ydCB0aGUgJHtKU09OLnN0cmluZ2lmeShwb2xpY3kpfSBwb2xpY3lgKVxuXHR9XG59XG5mdW5jdGlvbiBjcm9zc09yaWdpbkVtYmVkZGVyUG9saWN5KG9wdGlvbnMgPSB7fSkge1xuXHRjb25zdCBoZWFkZXJWYWx1ZSA9IGdldEhlYWRlclZhbHVlRnJvbU9wdGlvbnMkNyhvcHRpb25zKVxuXHRyZXR1cm4gZnVuY3Rpb24gY3Jvc3NPcmlnaW5FbWJlZGRlclBvbGljeU1pZGRsZXdhcmUoX3JlcSwgcmVzLCBuZXh0KSB7XG5cdFx0cmVzLnNldEhlYWRlcihcIkNyb3NzLU9yaWdpbi1FbWJlZGRlci1Qb2xpY3lcIiwgaGVhZGVyVmFsdWUpXG5cdFx0bmV4dCgpXG5cdH1cbn1cblxuY29uc3QgQUxMT1dFRF9QT0xJQ0lFUyQxID0gbmV3IFNldChbXCJzYW1lLW9yaWdpblwiLCBcInNhbWUtb3JpZ2luLWFsbG93LXBvcHVwc1wiLCBcInVuc2FmZS1ub25lXCJdKVxuZnVuY3Rpb24gZ2V0SGVhZGVyVmFsdWVGcm9tT3B0aW9ucyQ2KHtwb2xpY3kgPSBcInNhbWUtb3JpZ2luXCJ9KSB7XG5cdGlmIChBTExPV0VEX1BPTElDSUVTJDEuaGFzKHBvbGljeSkpIHtcblx0XHRyZXR1cm4gcG9saWN5XG5cdH0gZWxzZSB7XG5cdFx0dGhyb3cgbmV3IEVycm9yKGBDcm9zcy1PcmlnaW4tT3BlbmVyLVBvbGljeSBkb2VzIG5vdCBzdXBwb3J0IHRoZSAke0pTT04uc3RyaW5naWZ5KHBvbGljeSl9IHBvbGljeWApXG5cdH1cbn1cbmZ1bmN0aW9uIGNyb3NzT3JpZ2luT3BlbmVyUG9saWN5KG9wdGlvbnMgPSB7fSkge1xuXHRjb25zdCBoZWFkZXJWYWx1ZSA9IGdldEhlYWRlclZhbHVlRnJvbU9wdGlvbnMkNihvcHRpb25zKVxuXHRyZXR1cm4gZnVuY3Rpb24gY3Jvc3NPcmlnaW5PcGVuZXJQb2xpY3lNaWRkbGV3YXJlKF9yZXEsIHJlcywgbmV4dCkge1xuXHRcdHJlcy5zZXRIZWFkZXIoXCJDcm9zcy1PcmlnaW4tT3BlbmVyLVBvbGljeVwiLCBoZWFkZXJWYWx1ZSlcblx0XHRuZXh0KClcblx0fVxufVxuXG5jb25zdCBBTExPV0VEX1BPTElDSUVTID0gbmV3IFNldChbXCJzYW1lLW9yaWdpblwiLCBcInNhbWUtc2l0ZVwiLCBcImNyb3NzLW9yaWdpblwiXSlcbmZ1bmN0aW9uIGdldEhlYWRlclZhbHVlRnJvbU9wdGlvbnMkNSh7cG9saWN5ID0gXCJzYW1lLW9yaWdpblwifSkge1xuXHRpZiAoQUxMT1dFRF9QT0xJQ0lFUy5oYXMocG9saWN5KSkge1xuXHRcdHJldHVybiBwb2xpY3lcblx0fSBlbHNlIHtcblx0XHR0aHJvdyBuZXcgRXJyb3IoYENyb3NzLU9yaWdpbi1SZXNvdXJjZS1Qb2xpY3kgZG9lcyBub3Qgc3VwcG9ydCB0aGUgJHtKU09OLnN0cmluZ2lmeShwb2xpY3kpfSBwb2xpY3lgKVxuXHR9XG59XG5mdW5jdGlvbiBjcm9zc09yaWdpblJlc291cmNlUG9saWN5KG9wdGlvbnMgPSB7fSkge1xuXHRjb25zdCBoZWFkZXJWYWx1ZSA9IGdldEhlYWRlclZhbHVlRnJvbU9wdGlvbnMkNShvcHRpb25zKVxuXHRyZXR1cm4gZnVuY3Rpb24gY3Jvc3NPcmlnaW5SZXNvdXJjZVBvbGljeU1pZGRsZXdhcmUoX3JlcSwgcmVzLCBuZXh0KSB7XG5cdFx0cmVzLnNldEhlYWRlcihcIkNyb3NzLU9yaWdpbi1SZXNvdXJjZS1Qb2xpY3lcIiwgaGVhZGVyVmFsdWUpXG5cdFx0bmV4dCgpXG5cdH1cbn1cblxuZnVuY3Rpb24gcGFyc2VNYXhBZ2UkMSh2YWx1ZSA9IDApIHtcblx0aWYgKHZhbHVlID49IDAgJiYgTnVtYmVyLmlzRmluaXRlKHZhbHVlKSkge1xuXHRcdHJldHVybiBNYXRoLmZsb29yKHZhbHVlKVxuXHR9IGVsc2Uge1xuXHRcdHRocm93IG5ldyBFcnJvcihgRXhwZWN0LUNUOiAke0pTT04uc3RyaW5naWZ5KHZhbHVlKX0gaXMgbm90IGEgdmFsaWQgdmFsdWUgZm9yIG1heEFnZS4gUGxlYXNlIGNob29zZSBhIHBvc2l0aXZlIGludGVnZXIuYClcblx0fVxufVxuZnVuY3Rpb24gZ2V0SGVhZGVyVmFsdWVGcm9tT3B0aW9ucyQ0KG9wdGlvbnMpIHtcblx0Y29uc3QgZGlyZWN0aXZlcyA9IFtgbWF4LWFnZT0ke3BhcnNlTWF4QWdlJDEob3B0aW9ucy5tYXhBZ2UpfWBdXG5cdGlmIChvcHRpb25zLmVuZm9yY2UpIHtcblx0XHRkaXJlY3RpdmVzLnB1c2goXCJlbmZvcmNlXCIpXG5cdH1cblx0aWYgKG9wdGlvbnMucmVwb3J0VXJpKSB7XG5cdFx0ZGlyZWN0aXZlcy5wdXNoKGByZXBvcnQtdXJpPVwiJHtvcHRpb25zLnJlcG9ydFVyaX1cImApXG5cdH1cblx0cmV0dXJuIGRpcmVjdGl2ZXMuam9pbihcIiwgXCIpXG59XG5mdW5jdGlvbiBleHBlY3RDdChvcHRpb25zID0ge30pIHtcblx0Y29uc3QgaGVhZGVyVmFsdWUgPSBnZXRIZWFkZXJWYWx1ZUZyb21PcHRpb25zJDQob3B0aW9ucylcblx0cmV0dXJuIGZ1bmN0aW9uIGV4cGVjdEN0TWlkZGxld2FyZShfcmVxLCByZXMsIG5leHQpIHtcblx0XHRyZXMuc2V0SGVhZGVyKFwiRXhwZWN0LUNUXCIsIGhlYWRlclZhbHVlKVxuXHRcdG5leHQoKVxuXHR9XG59XG5cbmZ1bmN0aW9uIG9yaWdpbkFnZW50Q2x1c3RlcigpIHtcblx0cmV0dXJuIGZ1bmN0aW9uIG9yaWdpbkFnZW50Q2x1c3Rlck1pZGRsZXdhcmUoX3JlcSwgcmVzLCBuZXh0KSB7XG5cdFx0cmVzLnNldEhlYWRlcihcIk9yaWdpbi1BZ2VudC1DbHVzdGVyXCIsIFwiPzFcIilcblx0XHRuZXh0KClcblx0fVxufVxuXG5jb25zdCBBTExPV0VEX1RPS0VOUyA9IG5ldyBTZXQoW1wibm8tcmVmZXJyZXJcIiwgXCJuby1yZWZlcnJlci13aGVuLWRvd25ncmFkZVwiLCBcInNhbWUtb3JpZ2luXCIsIFwib3JpZ2luXCIsIFwic3RyaWN0LW9yaWdpblwiLCBcIm9yaWdpbi13aGVuLWNyb3NzLW9yaWdpblwiLCBcInN0cmljdC1vcmlnaW4td2hlbi1jcm9zcy1vcmlnaW5cIiwgXCJ1bnNhZmUtdXJsXCIsIFwiXCJdKVxuZnVuY3Rpb24gZ2V0SGVhZGVyVmFsdWVGcm9tT3B0aW9ucyQzKHtwb2xpY3kgPSBbXCJuby1yZWZlcnJlclwiXX0pIHtcblx0Y29uc3QgdG9rZW5zID0gdHlwZW9mIHBvbGljeSA9PT0gXCJzdHJpbmdcIiA/IFtwb2xpY3ldIDogcG9saWN5XG5cdGlmICh0b2tlbnMubGVuZ3RoID09PSAwKSB7XG5cdFx0dGhyb3cgbmV3IEVycm9yKFwiUmVmZXJyZXItUG9saWN5IHJlY2VpdmVkIG5vIHBvbGljeSB0b2tlbnNcIilcblx0fVxuXHRjb25zdCB0b2tlbnNTZWVuID0gbmV3IFNldCgpXG5cdHRva2Vucy5mb3JFYWNoKHRva2VuID0+IHtcblx0XHRpZiAoIUFMTE9XRURfVE9LRU5TLmhhcyh0b2tlbikpIHtcblx0XHRcdHRocm93IG5ldyBFcnJvcihgUmVmZXJyZXItUG9saWN5IHJlY2VpdmVkIGFuIHVuZXhwZWN0ZWQgcG9saWN5IHRva2VuICR7SlNPTi5zdHJpbmdpZnkodG9rZW4pfWApXG5cdFx0fSBlbHNlIGlmICh0b2tlbnNTZWVuLmhhcyh0b2tlbikpIHtcblx0XHRcdHRocm93IG5ldyBFcnJvcihgUmVmZXJyZXItUG9saWN5IHJlY2VpdmVkIGEgZHVwbGljYXRlIHBvbGljeSB0b2tlbiAke0pTT04uc3RyaW5naWZ5KHRva2VuKX1gKVxuXHRcdH1cblx0XHR0b2tlbnNTZWVuLmFkZCh0b2tlbilcblx0fSlcblx0cmV0dXJuIHRva2Vucy5qb2luKFwiLFwiKVxufVxuZnVuY3Rpb24gcmVmZXJyZXJQb2xpY3kob3B0aW9ucyA9IHt9KSB7XG5cdGNvbnN0IGhlYWRlclZhbHVlID0gZ2V0SGVhZGVyVmFsdWVGcm9tT3B0aW9ucyQzKG9wdGlvbnMpXG5cdHJldHVybiBmdW5jdGlvbiByZWZlcnJlclBvbGljeU1pZGRsZXdhcmUoX3JlcSwgcmVzLCBuZXh0KSB7XG5cdFx0cmVzLnNldEhlYWRlcihcIlJlZmVycmVyLVBvbGljeVwiLCBoZWFkZXJWYWx1ZSlcblx0XHRuZXh0KClcblx0fVxufVxuXG5jb25zdCBERUZBVUxUX01BWF9BR0UgPSAxODAgKiAyNCAqIDYwICogNjBcbmZ1bmN0aW9uIHBhcnNlTWF4QWdlKHZhbHVlID0gREVGQVVMVF9NQVhfQUdFKSB7XG5cdGlmICh2YWx1ZSA+PSAwICYmIE51bWJlci5pc0Zpbml0ZSh2YWx1ZSkpIHtcblx0XHRyZXR1cm4gTWF0aC5mbG9vcih2YWx1ZSlcblx0fSBlbHNlIHtcblx0XHR0aHJvdyBuZXcgRXJyb3IoYFN0cmljdC1UcmFuc3BvcnQtU2VjdXJpdHk6ICR7SlNPTi5zdHJpbmdpZnkodmFsdWUpfSBpcyBub3QgYSB2YWxpZCB2YWx1ZSBmb3IgbWF4QWdlLiBQbGVhc2UgY2hvb3NlIGEgcG9zaXRpdmUgaW50ZWdlci5gKVxuXHR9XG59XG5mdW5jdGlvbiBnZXRIZWFkZXJWYWx1ZUZyb21PcHRpb25zJDIob3B0aW9ucykge1xuXHRpZiAoXCJtYXhhZ2VcIiBpbiBvcHRpb25zKSB7XG5cdFx0dGhyb3cgbmV3IEVycm9yKFwiU3RyaWN0LVRyYW5zcG9ydC1TZWN1cml0eSByZWNlaXZlZCBhbiB1bnN1cHBvcnRlZCBwcm9wZXJ0eSwgYG1heGFnZWAuIERpZCB5b3UgbWVhbiB0byBwYXNzIGBtYXhBZ2VgP1wiKVxuXHR9XG5cdGlmIChcImluY2x1ZGVTdWJkb21haW5zXCIgaW4gb3B0aW9ucykge1xuXHRcdGNvbnNvbGUud2FybignU3RyaWN0LVRyYW5zcG9ydC1TZWN1cml0eSBtaWRkbGV3YXJlIHNob3VsZCB1c2UgYGluY2x1ZGVTdWJEb21haW5zYCBpbnN0ZWFkIG9mIGBpbmNsdWRlU3ViZG9tYWluc2AuIChUaGUgY29ycmVjdCBvbmUgaGFzIGFuIHVwcGVyY2FzZSBcIkRcIi4pJylcblx0fVxuXHRpZiAoXCJzZXRJZlwiIGluIG9wdGlvbnMpIHtcblx0XHRjb25zb2xlLndhcm4oXCJTdHJpY3QtVHJhbnNwb3J0LVNlY3VyaXR5IG1pZGRsZXdhcmUgbm8gbG9uZ2VyIHN1cHBvcnRzIHRoZSBgc2V0SWZgIHBhcmFtZXRlci4gU2VlIHRoZSBkb2N1bWVudGF0aW9uIGFuZCA8aHR0cHM6Ly9naXRodWIuY29tL2hlbG1ldGpzL2hlbG1ldC93aWtpL0NvbmRpdGlvbmFsbHktdXNpbmctbWlkZGxld2FyZT4gaWYgeW91IG5lZWQgaGVscCByZXBsaWNhdGluZyB0aGlzIGJlaGF2aW9yLlwiKVxuXHR9XG5cdGNvbnN0IGRpcmVjdGl2ZXMgPSBbYG1heC1hZ2U9JHtwYXJzZU1heEFnZShvcHRpb25zLm1heEFnZSl9YF1cblx0aWYgKG9wdGlvbnMuaW5jbHVkZVN1YkRvbWFpbnMgPT09IHVuZGVmaW5lZCB8fCBvcHRpb25zLmluY2x1ZGVTdWJEb21haW5zKSB7XG5cdFx0ZGlyZWN0aXZlcy5wdXNoKFwiaW5jbHVkZVN1YkRvbWFpbnNcIilcblx0fVxuXHRpZiAob3B0aW9ucy5wcmVsb2FkKSB7XG5cdFx0ZGlyZWN0aXZlcy5wdXNoKFwicHJlbG9hZFwiKVxuXHR9XG5cdHJldHVybiBkaXJlY3RpdmVzLmpvaW4oXCI7IFwiKVxufVxuZnVuY3Rpb24gc3RyaWN0VHJhbnNwb3J0U2VjdXJpdHkob3B0aW9ucyA9IHt9KSB7XG5cdGNvbnN0IGhlYWRlclZhbHVlID0gZ2V0SGVhZGVyVmFsdWVGcm9tT3B0aW9ucyQyKG9wdGlvbnMpXG5cdHJldHVybiBmdW5jdGlvbiBzdHJpY3RUcmFuc3BvcnRTZWN1cml0eU1pZGRsZXdhcmUoX3JlcSwgcmVzLCBuZXh0KSB7XG5cdFx0cmVzLnNldEhlYWRlcihcIlN0cmljdC1UcmFuc3BvcnQtU2VjdXJpdHlcIiwgaGVhZGVyVmFsdWUpXG5cdFx0bmV4dCgpXG5cdH1cbn1cblxuZnVuY3Rpb24geENvbnRlbnRUeXBlT3B0aW9ucygpIHtcblx0cmV0dXJuIGZ1bmN0aW9uIHhDb250ZW50VHlwZU9wdGlvbnNNaWRkbGV3YXJlKF9yZXEsIHJlcywgbmV4dCkge1xuXHRcdHJlcy5zZXRIZWFkZXIoXCJYLUNvbnRlbnQtVHlwZS1PcHRpb25zXCIsIFwibm9zbmlmZlwiKVxuXHRcdG5leHQoKVxuXHR9XG59XG5cbmZ1bmN0aW9uIHhEbnNQcmVmZXRjaENvbnRyb2wob3B0aW9ucyA9IHt9KSB7XG5cdGNvbnN0IGhlYWRlclZhbHVlID0gb3B0aW9ucy5hbGxvdyA/IFwib25cIiA6IFwib2ZmXCJcblx0cmV0dXJuIGZ1bmN0aW9uIHhEbnNQcmVmZXRjaENvbnRyb2xNaWRkbGV3YXJlKF9yZXEsIHJlcywgbmV4dCkge1xuXHRcdHJlcy5zZXRIZWFkZXIoXCJYLUROUy1QcmVmZXRjaC1Db250cm9sXCIsIGhlYWRlclZhbHVlKVxuXHRcdG5leHQoKVxuXHR9XG59XG5cbmZ1bmN0aW9uIHhEb3dubG9hZE9wdGlvbnMoKSB7XG5cdHJldHVybiBmdW5jdGlvbiB4RG93bmxvYWRPcHRpb25zTWlkZGxld2FyZShfcmVxLCByZXMsIG5leHQpIHtcblx0XHRyZXMuc2V0SGVhZGVyKFwiWC1Eb3dubG9hZC1PcHRpb25zXCIsIFwibm9vcGVuXCIpXG5cdFx0bmV4dCgpXG5cdH1cbn1cblxuZnVuY3Rpb24gZ2V0SGVhZGVyVmFsdWVGcm9tT3B0aW9ucyQxKHthY3Rpb24gPSBcInNhbWVvcmlnaW5cIn0pIHtcblx0Y29uc3Qgbm9ybWFsaXplZEFjdGlvbiA9IHR5cGVvZiBhY3Rpb24gPT09IFwic3RyaW5nXCIgPyBhY3Rpb24udG9VcHBlckNhc2UoKSA6IGFjdGlvblxuXHRzd2l0Y2ggKG5vcm1hbGl6ZWRBY3Rpb24pIHtcblx0XHRjYXNlIFwiU0FNRS1PUklHSU5cIjpcblx0XHRcdHJldHVybiBcIlNBTUVPUklHSU5cIlxuXHRcdGNhc2UgXCJERU5ZXCI6XG5cdFx0Y2FzZSBcIlNBTUVPUklHSU5cIjpcblx0XHRcdHJldHVybiBub3JtYWxpemVkQWN0aW9uXG5cdFx0ZGVmYXVsdDpcblx0XHRcdHRocm93IG5ldyBFcnJvcihgWC1GcmFtZS1PcHRpb25zIHJlY2VpdmVkIGFuIGludmFsaWQgYWN0aW9uICR7SlNPTi5zdHJpbmdpZnkoYWN0aW9uKX1gKVxuXHR9XG59XG5mdW5jdGlvbiB4RnJhbWVPcHRpb25zKG9wdGlvbnMgPSB7fSkge1xuXHRjb25zdCBoZWFkZXJWYWx1ZSA9IGdldEhlYWRlclZhbHVlRnJvbU9wdGlvbnMkMShvcHRpb25zKVxuXHRyZXR1cm4gZnVuY3Rpb24geEZyYW1lT3B0aW9uc01pZGRsZXdhcmUoX3JlcSwgcmVzLCBuZXh0KSB7XG5cdFx0cmVzLnNldEhlYWRlcihcIlgtRnJhbWUtT3B0aW9uc1wiLCBoZWFkZXJWYWx1ZSlcblx0XHRuZXh0KClcblx0fVxufVxuXG5jb25zdCBBTExPV0VEX1BFUk1JVFRFRF9QT0xJQ0lFUyA9IG5ldyBTZXQoW1wibm9uZVwiLCBcIm1hc3Rlci1vbmx5XCIsIFwiYnktY29udGVudC10eXBlXCIsIFwiYWxsXCJdKVxuZnVuY3Rpb24gZ2V0SGVhZGVyVmFsdWVGcm9tT3B0aW9ucyh7cGVybWl0dGVkUG9saWNpZXMgPSBcIm5vbmVcIn0pIHtcblx0aWYgKEFMTE9XRURfUEVSTUlUVEVEX1BPTElDSUVTLmhhcyhwZXJtaXR0ZWRQb2xpY2llcykpIHtcblx0XHRyZXR1cm4gcGVybWl0dGVkUG9saWNpZXNcblx0fSBlbHNlIHtcblx0XHR0aHJvdyBuZXcgRXJyb3IoYFgtUGVybWl0dGVkLUNyb3NzLURvbWFpbi1Qb2xpY2llcyBkb2VzIG5vdCBzdXBwb3J0ICR7SlNPTi5zdHJpbmdpZnkocGVybWl0dGVkUG9saWNpZXMpfWApXG5cdH1cbn1cbmZ1bmN0aW9uIHhQZXJtaXR0ZWRDcm9zc0RvbWFpblBvbGljaWVzKG9wdGlvbnMgPSB7fSkge1xuXHRjb25zdCBoZWFkZXJWYWx1ZSA9IGdldEhlYWRlclZhbHVlRnJvbU9wdGlvbnMob3B0aW9ucylcblx0cmV0dXJuIGZ1bmN0aW9uIHhQZXJtaXR0ZWRDcm9zc0RvbWFpblBvbGljaWVzTWlkZGxld2FyZShfcmVxLCByZXMsIG5leHQpIHtcblx0XHRyZXMuc2V0SGVhZGVyKFwiWC1QZXJtaXR0ZWQtQ3Jvc3MtRG9tYWluLVBvbGljaWVzXCIsIGhlYWRlclZhbHVlKVxuXHRcdG5leHQoKVxuXHR9XG59XG5cbmZ1bmN0aW9uIHhQb3dlcmVkQnkoKSB7XG5cdHJldHVybiBmdW5jdGlvbiB4UG93ZXJlZEJ5TWlkZGxld2FyZShfcmVxLCByZXMsIG5leHQpIHtcblx0XHRyZXMucmVtb3ZlSGVhZGVyKFwiWC1Qb3dlcmVkLUJ5XCIpXG5cdFx0bmV4dCgpXG5cdH1cbn1cblxuZnVuY3Rpb24geFhzc1Byb3RlY3Rpb24oKSB7XG5cdHJldHVybiBmdW5jdGlvbiB4WHNzUHJvdGVjdGlvbk1pZGRsZXdhcmUoX3JlcSwgcmVzLCBuZXh0KSB7XG5cdFx0cmVzLnNldEhlYWRlcihcIlgtWFNTLVByb3RlY3Rpb25cIiwgXCIwXCIpXG5cdFx0bmV4dCgpXG5cdH1cbn1cblxuZnVuY3Rpb24gZ2V0QXJncyhvcHRpb24sIG1pZGRsZXdhcmVDb25maWcgPSB7fSkge1xuXHRzd2l0Y2ggKG9wdGlvbikge1xuXHRcdGNhc2UgdW5kZWZpbmVkOlxuXHRcdGNhc2UgdHJ1ZTpcblx0XHRcdHJldHVybiBbXVxuXHRcdGNhc2UgZmFsc2U6XG5cdFx0XHRyZXR1cm4gbnVsbFxuXHRcdGRlZmF1bHQ6XG5cdFx0XHRpZiAobWlkZGxld2FyZUNvbmZpZy50YWtlc09wdGlvbnMgPT09IGZhbHNlKSB7XG5cdFx0XHRcdGNvbnNvbGUud2FybihgJHttaWRkbGV3YXJlQ29uZmlnLm5hbWV9IGRvZXMgbm90IHRha2Ugb3B0aW9ucy4gUmVtb3ZlIHRoZSBwcm9wZXJ0eSB0byBzaWxlbmNlIHRoaXMgd2FybmluZy5gKVxuXHRcdFx0XHRyZXR1cm4gW11cblx0XHRcdH0gZWxzZSB7XG5cdFx0XHRcdHJldHVybiBbb3B0aW9uXVxuXHRcdFx0fVxuXHR9XG59XG5mdW5jdGlvbiBnZXRNaWRkbGV3YXJlRnVuY3Rpb25zRnJvbU9wdGlvbnMob3B0aW9ucykge1xuXHRjb25zdCByZXN1bHQgPSBbXVxuXHRjb25zdCBjb250ZW50U2VjdXJpdHlQb2xpY3lBcmdzID0gZ2V0QXJncyhvcHRpb25zLmNvbnRlbnRTZWN1cml0eVBvbGljeSlcblx0aWYgKGNvbnRlbnRTZWN1cml0eVBvbGljeUFyZ3MpIHtcblx0XHRyZXN1bHQucHVzaChjb250ZW50U2VjdXJpdHlQb2xpY3koLi4uY29udGVudFNlY3VyaXR5UG9saWN5QXJncykpXG5cdH1cblx0Y29uc3QgY3Jvc3NPcmlnaW5FbWJlZGRlclBvbGljeUFyZ3MgPSBnZXRBcmdzKG9wdGlvbnMuY3Jvc3NPcmlnaW5FbWJlZGRlclBvbGljeSlcblx0aWYgKGNyb3NzT3JpZ2luRW1iZWRkZXJQb2xpY3lBcmdzKSB7XG5cdFx0cmVzdWx0LnB1c2goY3Jvc3NPcmlnaW5FbWJlZGRlclBvbGljeSguLi5jcm9zc09yaWdpbkVtYmVkZGVyUG9saWN5QXJncykpXG5cdH1cblx0Y29uc3QgY3Jvc3NPcmlnaW5PcGVuZXJQb2xpY3lBcmdzID0gZ2V0QXJncyhvcHRpb25zLmNyb3NzT3JpZ2luT3BlbmVyUG9saWN5KVxuXHRpZiAoY3Jvc3NPcmlnaW5PcGVuZXJQb2xpY3lBcmdzKSB7XG5cdFx0cmVzdWx0LnB1c2goY3Jvc3NPcmlnaW5PcGVuZXJQb2xpY3koLi4uY3Jvc3NPcmlnaW5PcGVuZXJQb2xpY3lBcmdzKSlcblx0fVxuXHRjb25zdCBjcm9zc09yaWdpblJlc291cmNlUG9saWN5QXJncyA9IGdldEFyZ3Mob3B0aW9ucy5jcm9zc09yaWdpblJlc291cmNlUG9saWN5KVxuXHRpZiAoY3Jvc3NPcmlnaW5SZXNvdXJjZVBvbGljeUFyZ3MpIHtcblx0XHRyZXN1bHQucHVzaChjcm9zc09yaWdpblJlc291cmNlUG9saWN5KC4uLmNyb3NzT3JpZ2luUmVzb3VyY2VQb2xpY3lBcmdzKSlcblx0fVxuXHRjb25zdCB4RG5zUHJlZmV0Y2hDb250cm9sQXJncyA9IGdldEFyZ3Mob3B0aW9ucy5kbnNQcmVmZXRjaENvbnRyb2wpXG5cdGlmICh4RG5zUHJlZmV0Y2hDb250cm9sQXJncykge1xuXHRcdHJlc3VsdC5wdXNoKHhEbnNQcmVmZXRjaENvbnRyb2woLi4ueERuc1ByZWZldGNoQ29udHJvbEFyZ3MpKVxuXHR9XG5cdGNvbnN0IGV4cGVjdEN0QXJncyA9IG9wdGlvbnMuZXhwZWN0Q3QgJiYgZ2V0QXJncyhvcHRpb25zLmV4cGVjdEN0KVxuXHRpZiAoZXhwZWN0Q3RBcmdzKSB7XG5cdFx0cmVzdWx0LnB1c2goZXhwZWN0Q3QoLi4uZXhwZWN0Q3RBcmdzKSlcblx0fVxuXHRjb25zdCB4RnJhbWVPcHRpb25zQXJncyA9IGdldEFyZ3Mob3B0aW9ucy5mcmFtZWd1YXJkKVxuXHRpZiAoeEZyYW1lT3B0aW9uc0FyZ3MpIHtcblx0XHRyZXN1bHQucHVzaCh4RnJhbWVPcHRpb25zKC4uLnhGcmFtZU9wdGlvbnNBcmdzKSlcblx0fVxuXHRjb25zdCB4UG93ZXJlZEJ5QXJncyA9IGdldEFyZ3Mob3B0aW9ucy5oaWRlUG93ZXJlZEJ5LCB7XG5cdFx0bmFtZTogXCJoaWRlUG93ZXJlZEJ5XCIsXG5cdFx0dGFrZXNPcHRpb25zOiBmYWxzZVxuXHR9KVxuXHRpZiAoeFBvd2VyZWRCeUFyZ3MpIHtcblx0XHRyZXN1bHQucHVzaCh4UG93ZXJlZEJ5KCkpXG5cdH1cblx0Y29uc3Qgc3RyaWN0VHJhbnNwb3J0U2VjdXJpdHlBcmdzID0gZ2V0QXJncyhvcHRpb25zLmhzdHMpXG5cdGlmIChzdHJpY3RUcmFuc3BvcnRTZWN1cml0eUFyZ3MpIHtcblx0XHRyZXN1bHQucHVzaChzdHJpY3RUcmFuc3BvcnRTZWN1cml0eSguLi5zdHJpY3RUcmFuc3BvcnRTZWN1cml0eUFyZ3MpKVxuXHR9XG5cdGNvbnN0IHhEb3dubG9hZE9wdGlvbnNBcmdzID0gZ2V0QXJncyhvcHRpb25zLmllTm9PcGVuLCB7XG5cdFx0bmFtZTogXCJpZU5vT3BlblwiLFxuXHRcdHRha2VzT3B0aW9uczogZmFsc2Vcblx0fSlcblx0aWYgKHhEb3dubG9hZE9wdGlvbnNBcmdzKSB7XG5cdFx0cmVzdWx0LnB1c2goeERvd25sb2FkT3B0aW9ucygpKVxuXHR9XG5cdGNvbnN0IHhDb250ZW50VHlwZU9wdGlvbnNBcmdzID0gZ2V0QXJncyhvcHRpb25zLm5vU25pZmYsIHtcblx0XHRuYW1lOiBcIm5vU25pZmZcIixcblx0XHR0YWtlc09wdGlvbnM6IGZhbHNlXG5cdH0pXG5cdGlmICh4Q29udGVudFR5cGVPcHRpb25zQXJncykge1xuXHRcdHJlc3VsdC5wdXNoKHhDb250ZW50VHlwZU9wdGlvbnMoKSlcblx0fVxuXHRjb25zdCBvcmlnaW5BZ2VudENsdXN0ZXJBcmdzID0gZ2V0QXJncyhvcHRpb25zLm9yaWdpbkFnZW50Q2x1c3Rlciwge1xuXHRcdG5hbWU6IFwib3JpZ2luQWdlbnRDbHVzdGVyXCIsXG5cdFx0dGFrZXNPcHRpb25zOiBmYWxzZVxuXHR9KVxuXHRpZiAob3JpZ2luQWdlbnRDbHVzdGVyQXJncykge1xuXHRcdHJlc3VsdC5wdXNoKG9yaWdpbkFnZW50Q2x1c3RlcigpKVxuXHR9XG5cdGNvbnN0IHhQZXJtaXR0ZWRDcm9zc0RvbWFpblBvbGljaWVzQXJncyA9IGdldEFyZ3Mob3B0aW9ucy5wZXJtaXR0ZWRDcm9zc0RvbWFpblBvbGljaWVzKVxuXHRpZiAoeFBlcm1pdHRlZENyb3NzRG9tYWluUG9saWNpZXNBcmdzKSB7XG5cdFx0cmVzdWx0LnB1c2goeFBlcm1pdHRlZENyb3NzRG9tYWluUG9saWNpZXMoLi4ueFBlcm1pdHRlZENyb3NzRG9tYWluUG9saWNpZXNBcmdzKSlcblx0fVxuXHRjb25zdCByZWZlcnJlclBvbGljeUFyZ3MgPSBnZXRBcmdzKG9wdGlvbnMucmVmZXJyZXJQb2xpY3kpXG5cdGlmIChyZWZlcnJlclBvbGljeUFyZ3MpIHtcblx0XHRyZXN1bHQucHVzaChyZWZlcnJlclBvbGljeSguLi5yZWZlcnJlclBvbGljeUFyZ3MpKVxuXHR9XG5cdGNvbnN0IHhYc3NQcm90ZWN0aW9uQXJncyA9IGdldEFyZ3Mob3B0aW9ucy54c3NGaWx0ZXIsIHtcblx0XHRuYW1lOiBcInhzc0ZpbHRlclwiLFxuXHRcdHRha2VzT3B0aW9uczogZmFsc2Vcblx0fSlcblx0aWYgKHhYc3NQcm90ZWN0aW9uQXJncykge1xuXHRcdHJlc3VsdC5wdXNoKHhYc3NQcm90ZWN0aW9uKCkpXG5cdH1cblx0cmV0dXJuIHJlc3VsdFxufVxuY29uc3QgaGVsbWV0ID0gT2JqZWN0LmFzc2lnbihcblx0ZnVuY3Rpb24gaGVsbWV0KG9wdGlvbnMgPSB7fSkge1xuXHRcdHZhciBfYVxuXHRcdC8vIFBlb3BsZSBzaG91bGQgYmUgYWJsZSB0byBwYXNzIGFuIG9wdGlvbnMgb2JqZWN0IHdpdGggbm8gcHJvdG90eXBlLFxuXHRcdC8vIHNvIHdlIHdhbnQgdGhpcyBvcHRpb25hbCBjaGFpbmluZy5cblx0XHQvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgQHR5cGVzY3JpcHQtZXNsaW50L25vLXVubmVjZXNzYXJ5LWNvbmRpdGlvblxuXHRcdGlmICgoKF9hID0gb3B0aW9ucy5jb25zdHJ1Y3RvcikgPT09IG51bGwgfHwgX2EgPT09IHZvaWQgMCA/IHZvaWQgMCA6IF9hLm5hbWUpID09PSBcIkluY29taW5nTWVzc2FnZVwiKSB7XG5cdFx0XHR0aHJvdyBuZXcgRXJyb3IoXCJJdCBhcHBlYXJzIHlvdSBoYXZlIGRvbmUgc29tZXRoaW5nIGxpa2UgYGFwcC51c2UoaGVsbWV0KWAsIGJ1dCBpdCBzaG91bGQgYmUgYGFwcC51c2UoaGVsbWV0KCkpYC5cIilcblx0XHR9XG5cdFx0Y29uc3QgbWlkZGxld2FyZUZ1bmN0aW9ucyA9IGdldE1pZGRsZXdhcmVGdW5jdGlvbnNGcm9tT3B0aW9ucyhvcHRpb25zKVxuXHRcdHJldHVybiBmdW5jdGlvbiBoZWxtZXRNaWRkbGV3YXJlKHJlcSwgcmVzLCBuZXh0KSB7XG5cdFx0XHRsZXQgbWlkZGxld2FyZUluZGV4ID0gMFxuXHRcdFx0OyhmdW5jdGlvbiBpbnRlcm5hbE5leHQoZXJyKSB7XG5cdFx0XHRcdGlmIChlcnIpIHtcblx0XHRcdFx0XHRuZXh0KGVycilcblx0XHRcdFx0XHRyZXR1cm5cblx0XHRcdFx0fVxuXHRcdFx0XHRjb25zdCBtaWRkbGV3YXJlRnVuY3Rpb24gPSBtaWRkbGV3YXJlRnVuY3Rpb25zW21pZGRsZXdhcmVJbmRleF1cblx0XHRcdFx0aWYgKG1pZGRsZXdhcmVGdW5jdGlvbikge1xuXHRcdFx0XHRcdG1pZGRsZXdhcmVJbmRleCsrXG5cdFx0XHRcdFx0bWlkZGxld2FyZUZ1bmN0aW9uKHJlcSwgcmVzLCBpbnRlcm5hbE5leHQpXG5cdFx0XHRcdH0gZWxzZSB7XG5cdFx0XHRcdFx0bmV4dCgpXG5cdFx0XHRcdH1cblx0XHRcdH0pKClcblx0XHR9XG5cdH0sXG5cdHtcblx0XHRjb250ZW50U2VjdXJpdHlQb2xpY3ksXG5cdFx0Y3Jvc3NPcmlnaW5FbWJlZGRlclBvbGljeSxcblx0XHRjcm9zc09yaWdpbk9wZW5lclBvbGljeSxcblx0XHRjcm9zc09yaWdpblJlc291cmNlUG9saWN5LFxuXHRcdGRuc1ByZWZldGNoQ29udHJvbDogeERuc1ByZWZldGNoQ29udHJvbCxcblx0XHRleHBlY3RDdCxcblx0XHRmcmFtZWd1YXJkOiB4RnJhbWVPcHRpb25zLFxuXHRcdGhpZGVQb3dlcmVkQnk6IHhQb3dlcmVkQnksXG5cdFx0aHN0czogc3RyaWN0VHJhbnNwb3J0U2VjdXJpdHksXG5cdFx0aWVOb09wZW46IHhEb3dubG9hZE9wdGlvbnMsXG5cdFx0bm9TbmlmZjogeENvbnRlbnRUeXBlT3B0aW9ucyxcblx0XHRvcmlnaW5BZ2VudENsdXN0ZXIsXG5cdFx0cGVybWl0dGVkQ3Jvc3NEb21haW5Qb2xpY2llczogeFBlcm1pdHRlZENyb3NzRG9tYWluUG9saWNpZXMsXG5cdFx0cmVmZXJyZXJQb2xpY3ksXG5cdFx0eHNzRmlsdGVyOiB4WHNzUHJvdGVjdGlvblxuXHR9XG4pXG5cbmV4cG9ydCB7Y29udGVudFNlY3VyaXR5UG9saWN5LCBjcm9zc09yaWdpbkVtYmVkZGVyUG9saWN5LCBjcm9zc09yaWdpbk9wZW5lclBvbGljeSwgY3Jvc3NPcmlnaW5SZXNvdXJjZVBvbGljeSwgaGVsbWV0IGFzIGRlZmF1bHQsIHhEbnNQcmVmZXRjaENvbnRyb2wgYXMgZG5zUHJlZmV0Y2hDb250cm9sLCBleHBlY3RDdCwgeEZyYW1lT3B0aW9ucyBhcyBmcmFtZWd1YXJkLCB4UG93ZXJlZEJ5IGFzIGhpZGVQb3dlcmVkQnksIHN0cmljdFRyYW5zcG9ydFNlY3VyaXR5IGFzIGhzdHMsIHhEb3dubG9hZE9wdGlvbnMgYXMgaWVOb09wZW4sIHhDb250ZW50VHlwZU9wdGlvbnMgYXMgbm9TbmlmZiwgb3JpZ2luQWdlbnRDbHVzdGVyLCB4UGVybWl0dGVkQ3Jvc3NEb21haW5Qb2xpY2llcyBhcyBwZXJtaXR0ZWRDcm9zc0RvbWFpblBvbGljaWVzLCByZWZlcnJlclBvbGljeSwgeFhzc1Byb3RlY3Rpb24gYXMgeHNzRmlsdGVyfVxuIiwiLy8gZ2xvYmFsXG5leHBvcnQgY29uc3QgSU5URVJOQUxfU0VSVkVSID0gJ9CS0LjQvdC40LrQu9CwINC/0L7QvNC40LvQutCwJztcbmV4cG9ydCBjb25zdCBJTlZBTElEX0RBVEEgPSAn0J3QtdC60L7RgNC10LrRgtC90ZYg0LTQsNC90ZYnO1xuLy8gZGF0YVxuZXhwb3J0IGNvbnN0IE5PVF9GT1VORCA9ICfQntCxYNGU0LrRgiDQvdC1INC30L3QsNC50LTQtdC90L4nO1xuLy8gbG9naW5cbmV4cG9ydCBjb25zdCBMT0dJTiA9ICfQndC10L/RgNCw0LLQuNC70YzQvdC40Lkg0LvQvtCz0ZbQvSDQsNCx0L4g0L/QsNGA0L7Qu9GMJztcbiIsIi8vIDIwMFxuZXhwb3J0IGNvbnN0IE9LID0gMjAwO1xuZXhwb3J0IGNvbnN0IENSRUFURUQgPSAyMDE7XG5leHBvcnQgY29uc3QgQUNDRVBURUQgPSAyMDI7XG5leHBvcnQgY29uc3QgTk9fQ09OVEVOVCA9IDIwNDtcbi8vIDQwMFxuZXhwb3J0IGNvbnN0IEJBRF9SRVFVRVNUID0gNDAwO1xuZXhwb3J0IGNvbnN0IFVOQVVUSE9SSVpFRCA9IDQwMTtcbmV4cG9ydCBjb25zdCBGT1JCSURERU4gPSA0MDM7XG5leHBvcnQgY29uc3QgTk9UX0ZPVU5EID0gNDA0O1xuZXhwb3J0IGNvbnN0IE1FVEhPRF9OT1RfQUxMT1dFRCA9IDQwNTtcbmV4cG9ydCBjb25zdCBOT1RfQUNDRVBUQUJMRSA9IDQwNjtcbmV4cG9ydCBjb25zdCBSRVFVRVNUX1RJTUVPVVQgPSA0MDg7XG5leHBvcnQgY29uc3QgQ09ORkxJQ1QgPSA0MDk7XG5leHBvcnQgY29uc3QgUEFZTE9BRF9UT09fTEFSR0UgPSA0MTM7XG5leHBvcnQgY29uc3QgVVJJX1RPT19MT05HID0gNDE0O1xuZXhwb3J0IGNvbnN0IFVOU1VQUE9SVEVEX01FRElBX1RZUEUgPSA0MTU7XG5leHBvcnQgY29uc3QgUkFOR0VfTk9UX1NBVElTRklBQkxFID0gNDE2O1xuZXhwb3J0IGNvbnN0IFRPT19NQU5ZX1JFUVVFU1RTID0gNDI5O1xuZXhwb3J0IGNvbnN0IFJFUVVFU1RfSEVBREVSX0ZJRUxEU19UT09fTEFSR0UgPSA0MzE7XG5leHBvcnQgY29uc3QgVU5BVkFJTEFCTEVfRk9SX0xFR0FMX1JFQVNPTlMgPSA0NTE7XG4vLyA1MDBcbmV4cG9ydCBjb25zdCBJTlRFUk5BTF9TRVJWRVJfRVJST1IgPSA1MDA7XG5leHBvcnQgY29uc3QgTk9UX0lNUExFTUVOVEVEID0gNTAxO1xuZXhwb3J0IGNvbnN0IEJBRF9HQVRFV0FZID0gNTAyO1xuZXhwb3J0IGNvbnN0IFNFUlZJQ0VfVU5BVkFJTEFCTEUgPSA1MDM7XG5leHBvcnQgY29uc3QgR0FURVdBWV9USU1FT1VUID0gNTA0O1xuZXhwb3J0IGNvbnN0IExPT1BfREVURUNURUQgPSA1MDg7XG5leHBvcnQgY29uc3QgTkVUV09SS19BVVRIRU5USUNBVElPTl9SRVFVSVJFRCA9IDUxMTtcbiIsImltcG9ydCAqIGFzIEVSUk9SIGZyb20gJy4vZXJyb3JNZXNzYWdlcyc7XG5pbXBvcnQgKiBhcyBTVEFUVVMgZnJvbSAnLi9zdGF0dXNDb2Rlcyc7XG5leHBvcnQgY2xhc3MgQXBpRXJyb3Ige1xuICAgIHN0YXR1cztcbiAgICBtZXNzYWdlO1xuICAgIGVycm9yO1xuICAgIGNvbnN0cnVjdG9yKHBhcmFtcykge1xuICAgICAgICBjb25zdCB7IHN0YXR1cywgbWVzc2FnZSwgZXJyb3IgfSA9IHBhcmFtcztcbiAgICAgICAgdGhpcy5zdGF0dXMgPSBzdGF0dXM7XG4gICAgICAgIHRoaXMubWVzc2FnZSA9IG1lc3NhZ2U7XG4gICAgICAgIHRoaXMuZXJyb3IgPSBlcnJvciA/PyAnJztcbiAgICB9XG4gICAgc3RhdGljIGludGVybmFsU2VydmVyRXJyb3IoZXJyb3IpIHtcbiAgICAgICAgcmV0dXJuIG5ldyBBcGlFcnJvcih7XG4gICAgICAgICAgICBzdGF0dXM6IFNUQVRVUy5JTlRFUk5BTF9TRVJWRVJfRVJST1IsXG4gICAgICAgICAgICBtZXNzYWdlOiBFUlJPUi5JTlRFUk5BTF9TRVJWRVIsXG4gICAgICAgICAgICBlcnJvcixcbiAgICAgICAgfSk7XG4gICAgfVxuICAgIC8vIFRPRE8gaW1wbGVtZW50XG4gICAgbm90aWZ5KCkgeyB9XG59XG4iLCJleHBvcnQgY2xhc3MgQXBpU3VjY2VzcyB7XG4gICAgc3RhdHVzO1xuICAgIG1lc3NhZ2U7XG4gICAgZGF0YTtcbiAgICBjb25zdHJ1Y3RvcihwYXJhbXMpIHtcbiAgICAgICAgY29uc3QgeyBzdGF0dXMsIG1lc3NhZ2UsIGRhdGEgfSA9IHBhcmFtcztcbiAgICAgICAgdGhpcy5zdGF0dXMgPSBzdGF0dXM7XG4gICAgICAgIHRoaXMubWVzc2FnZSA9IG1lc3NhZ2U7XG4gICAgICAgIHRoaXMuZGF0YSA9IGRhdGE7XG4gICAgfVxufVxuIiwiaW1wb3J0IHsgQXBpRXJyb3IsIFNUQVRVUyB9IGZyb20gJ0AvYXBpL3Jlc3BvbnNlcyc7XG5leHBvcnQgY29uc3QgcG9zdCA9IGFzeW5jIChyZXEsIHJlcykgPT4ge1xuICAgIHRyeSB7XG4gICAgICAgIGNvbnN0IHsgZW1haWwsIHBhc3N3b3JkIH0gPSByZXEuYm9keTtcbiAgICAgICAgaWYgKGVtYWlsID09PSB1bmRlZmluZWQgfHwgcGFzc3dvcmQgPT09IHVuZGVmaW5lZCkge1xuICAgICAgICAgICAgY29uc3QgcmVzcG9uc2UgPSBuZXcgQXBpRXJyb3Ioe1xuICAgICAgICAgICAgICAgIHN0YXR1czogU1RBVFVTLkJBRF9SRVFVRVNULFxuICAgICAgICAgICAgICAgIG1lc3NhZ2U6ICdFbWFpbCBvciBwYXNzd29yZCBpcyBtaXNzaW5nJyxcbiAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgcmV0dXJuIHJlcy5zdGF0dXMocmVzcG9uc2Uuc3RhdHVzKS5zZW5kKHJlc3BvbnNlKTtcbiAgICAgICAgfVxuICAgICAgICAvLyBjb25zdFxuICAgIH1cbiAgICBjYXRjaCAoZXJyb3IpIHtcbiAgICAgICAgY29uc3QgcmVzcG9uc2UgPSBBcGlFcnJvci5pbnRlcm5hbFNlcnZlckVycm9yKGVycm9yKTtcbiAgICAgICAgcmV0dXJuIHJlcy5zdGF0dXMocmVzcG9uc2Uuc3RhdHVzKS5zZW5kKHJlc3BvbnNlKTtcbiAgICB9XG4gICAgZmluYWxseSB7XG4gICAgICAgIHJlcy5lbmQoKTtcbiAgICB9XG59O1xuIiwiaW1wb3J0IHsgUm91dGVyIH0gZnJvbSAnZXhwcmVzcyc7XG5pbXBvcnQgeyBwb3N0IH0gZnJvbSAnQC9hcGkvY29udHJvbGxlcnMvbG9naW4nO1xuY29uc3QgbG9naW5Sb3V0ZXIgPSBSb3V0ZXIoKTtcbmxvZ2luUm91dGVyLmdldCgnLycsIHBvc3QpO1xuZXhwb3J0IHsgbG9naW5Sb3V0ZXIgfTtcbiIsImltcG9ydCB7IFNjaGVtYSwgbW9kZWwsIG1vZGVscyB9IGZyb20gJ21vbmdvb3NlJztcbmNvbnN0IExhYlNjaGVtYSA9IG5ldyBTY2hlbWEoe1xuICAgIG5hbWU6IHtcbiAgICAgICAgdHlwZTogU3RyaW5nLFxuICAgICAgICByZXF1aXJlZDogdHJ1ZSxcbiAgICB9LFxuICAgIHJhdGluZzoge1xuICAgICAgICB0eXBlOiBOdW1iZXIsXG4gICAgICAgIHJlcXVpcmVkOiB0cnVlLFxuICAgIH0sXG4gICAgbWVzc2FnZToge1xuICAgICAgICB0eXBlOiBTdHJpbmcsXG4gICAgICAgIHJlcXVpcmVkOiB0cnVlLFxuICAgIH0sXG59KTtcbmV4cG9ydCBjb25zdCBEaXNjaXBsaW5lU2NoZW1hID0gbmV3IFNjaGVtYSh7XG4gICAgbmFtZToge1xuICAgICAgICB0eXBlOiBTdHJpbmcsXG4gICAgICAgIHJlcXVpcmVkOiB0cnVlLFxuICAgIH0sXG4gICAgdGVhY2hlcjoge1xuICAgICAgICB0eXBlOiBTdHJpbmcsXG4gICAgICAgIHJlcXVpcmVkOiB0cnVlLFxuICAgIH0sXG4gICAgdGVhY2hlckVtYWlsOiB7XG4gICAgICAgIHR5cGU6IFN0cmluZyxcbiAgICAgICAgcmVxdWlyZWQ6IHRydWUsXG4gICAgfSxcbiAgICBsYWJzOiB7XG4gICAgICAgIHR5cGU6IFtMYWJTY2hlbWFdLFxuICAgICAgICByZXF1aXJlZDogdHJ1ZSxcbiAgICB9LFxufSk7XG5jb25zdCBTcGVjaWFsaXRpZVNjaGVtYSA9IG5ldyBTY2hlbWEoe1xuICAgIGlkOiB7XG4gICAgICAgIHR5cGU6IFN0cmluZyxcbiAgICAgICAgcmVxdWlyZWQ6IHRydWUsXG4gICAgfSxcbiAgICBuYW1lOiB7XG4gICAgICAgIHR5cGU6IFN0cmluZyxcbiAgICAgICAgcmVxdWlyZWQ6IHRydWUsXG4gICAgfSxcbiAgICBkaXNjaXBsaW5lczoge1xuICAgICAgICB0eXBlOiBbRGlzY2lwbGluZVNjaGVtYV0sXG4gICAgICAgIHJlcXVpcmVkOiB0cnVlLFxuICAgIH0sXG59KTtcbmNvbnN0IFVuaXZlcnNpdHlTY2hlbWEgPSBuZXcgU2NoZW1hKHtcbiAgICBfaWQ6IHtcbiAgICAgICAgdHlwZTogTnVtYmVyLFxuICAgICAgICByZXF1aXJlZDogdHJ1ZSxcbiAgICB9LFxuICAgIGlkOiB7XG4gICAgICAgIHR5cGU6IFN0cmluZyxcbiAgICAgICAgcmVxdWlyZWQ6IHRydWUsXG4gICAgfSxcbiAgICBuYW1lOiB7XG4gICAgICAgIHR5cGU6IFN0cmluZyxcbiAgICAgICAgcmVxdWlyZWQ6IHRydWUsXG4gICAgfSxcbiAgICBhYmJyOiB7XG4gICAgICAgIHR5cGU6IFN0cmluZyxcbiAgICAgICAgcmVxdWlyZWQ6IHRydWUsXG4gICAgfSxcbiAgICBzcGVjaWFsaXRpZXM6IHtcbiAgICAgICAgdHlwZTogW1NwZWNpYWxpdGllU2NoZW1hXSxcbiAgICAgICAgcmVxdWlyZWQ6IHRydWUsXG4gICAgfSxcbn0pO1xuZXhwb3J0IGNvbnN0IFVuaXZlcnNpdHlNb2RlbCA9IG1vZGVscy5Vbml2ZXJzaXR5ID8/IG1vZGVsKCdVbml2ZXJzaXR5JywgVW5pdmVyc2l0eVNjaGVtYSk7XG4iLCJpbXBvcnQgeyBVbml2ZXJzaXR5TW9kZWwgfSBmcm9tICdAL0RhdGFiYXNlL21vZGVscyc7XG5pbXBvcnQgeyBBcGlFcnJvciwgQXBpU3VjY2VzcywgU1RBVFVTIH0gZnJvbSAnQC9hcGkvcmVzcG9uc2VzJztcbmV4cG9ydCBjb25zdCBnZXQgPSBhc3luYyAocmVxLCByZXMpID0+IHtcbiAgICB0cnkge1xuICAgICAgICBjb25zdCB1bml2ZXJzaXRpZXMgPSBhd2FpdCBVbml2ZXJzaXR5TW9kZWwuZmluZCgpLmxlYW4oKTtcbiAgICAgICAgY29uc3QgZGF0YSA9IHVuaXZlcnNpdGllcy5maW5kKChpdGVtKSA9PiBpdGVtLmFiYnIgPT09ICdMUE5VJyk7XG4gICAgICAgIGNvbnN0IHJlc3BvbnNlID0gbmV3IEFwaVN1Y2Nlc3Moe1xuICAgICAgICAgICAgc3RhdHVzOiBTVEFUVVMuT0ssXG4gICAgICAgICAgICBtZXNzYWdlOiAnU3VjY2VzcycsXG4gICAgICAgICAgICBkYXRhLFxuICAgICAgICB9KTtcbiAgICAgICAgcmV0dXJuIHJlcy5zdGF0dXMocmVzcG9uc2Uuc3RhdHVzKS5zZW5kKHJlc3BvbnNlKTtcbiAgICB9XG4gICAgY2F0Y2ggKGVycm9yKSB7XG4gICAgICAgIGNvbnN0IHJlc3BvbnNlID0gQXBpRXJyb3IuaW50ZXJuYWxTZXJ2ZXJFcnJvcihlcnJvcik7XG4gICAgICAgIHJldHVybiByZXMuc3RhdHVzKHJlc3BvbnNlLnN0YXR1cykuc2VuZChyZXNwb25zZSk7XG4gICAgfVxuICAgIGZpbmFsbHkge1xuICAgICAgICByZXMuZW5kKCk7XG4gICAgfVxufTtcbiIsImltcG9ydCB7IFJvdXRlciB9IGZyb20gJ2V4cHJlc3MnO1xuaW1wb3J0IHsgZ2V0IH0gZnJvbSAnQC9hcGkvY29udHJvbGxlcnMvdW5pdmVyc2l0eSc7XG5jb25zdCB1bml2ZXJzaXR5Um91dGVyID0gUm91dGVyKCk7XG51bml2ZXJzaXR5Um91dGVyLmdldCgnLycsIGdldCk7XG5leHBvcnQgeyB1bml2ZXJzaXR5Um91dGVyIH07XG4iLCJpbXBvcnQgeyBSb3V0ZXIgfSBmcm9tICdleHByZXNzJztcbmltcG9ydCB7IHVuaXZlcnNpdHlSb3V0ZXIgfSBmcm9tICcuL3JvdXRlcyc7XG5jb25zdCBhcGlSb3V0ZXIgPSBSb3V0ZXIoKTtcbmFwaVJvdXRlci51c2UoJy91bml2ZXJzaXR5JywgdW5pdmVyc2l0eVJvdXRlcik7XG5leHBvcnQgeyBhcGlSb3V0ZXIgfTtcbiIsImltcG9ydCBib2R5UGFyc2VyIGZyb20gJ2JvZHktcGFyc2VyJztcbmltcG9ydCBjb21wcmVzc2lvbiBmcm9tICdjb21wcmVzc2lvbic7XG5pbXBvcnQgY29ycyBmcm9tICdjb3JzJztcbmltcG9ydCBleHByZXNzIGZyb20gJ2V4cHJlc3MnO1xuaW1wb3J0IGhlbG1ldCBmcm9tICdoZWxtZXQnO1xuaW1wb3J0IHsgYXBpUm91dGVyIH0gZnJvbSAnQC9hcGknO1xuY29uc3Qgc2VydmVyID0gZXhwcmVzcygpO1xudHJ5IHtcbiAgICBzZXJ2ZXIudXNlKGJvZHlQYXJzZXIudXJsZW5jb2RlZCh7IGV4dGVuZGVkOiB0cnVlIH0pKTtcbiAgICBzZXJ2ZXIudXNlKGJvZHlQYXJzZXIuanNvbigpKTtcbiAgICBzZXJ2ZXIudXNlKGNvbXByZXNzaW9uKCkpO1xuICAgIHNlcnZlci51c2UoY29ycygpKTtcbiAgICBzZXJ2ZXIudXNlKGhlbG1ldCh7XG4gICAgICAgIGNvbnRlbnRTZWN1cml0eVBvbGljeTogZmFsc2UsXG4gICAgfSkpO1xuICAgIHNlcnZlci51c2UoJy9hcGknLCBhcGlSb3V0ZXIpO1xuICAgIGNvbnNvbGUubG9nKCdbU0VSVkVSXSBJbml0aWFsaXplZCcpO1xufVxuY2F0Y2ggKGVycm9yKSB7XG4gICAgY29uc29sZS5lcnJvcihlcnJvcik7XG59XG5leHBvcnQgeyBzZXJ2ZXIgfTtcbiIsImltcG9ydCB7IGNvbmZpZyB9IGZyb20gJ2RvdGVudic7XG5jb25maWcoKTtcbi8vIGdsb2JhbFxuZXhwb3J0IGNvbnN0IFBPUlQgPSBwcm9jZXNzLmVudi5QT1JUID8/IDQwMDA7XG4vLyBkYXRhYmFzZVxuLy8gZGF0YWJhc2VcbmV4cG9ydCBjb25zdCBEQl9VU0VSID0gcHJvY2Vzcy5lbnYuREJfVVNFUjtcbmV4cG9ydCBjb25zdCBEQl9QQVNTID0gcHJvY2Vzcy5lbnYuREJfUEFTUztcbmV4cG9ydCBjb25zdCBEQl9OQU1FID0gcHJvY2Vzcy5lbnYuREJfTkFNRTtcbmV4cG9ydCBjb25zdCBEQl9DT05OU1RSID0gcHJvY2Vzcy5lbnYuREJfQ09OTlNUUlxuICAgIC5yZXBsYWNlKCc8dXNlcj4nLCBEQl9VU0VSKVxuICAgIC5yZXBsYWNlKCc8cGFzcz4nLCBEQl9QQVNTKVxuICAgIC5yZXBsYWNlKCc8ZGI+JywgREJfTkFNRSk7XG4iLCJpbXBvcnQgeyBjb25uZWN0LCBjb25uZWN0aW9uLCBzZXQgfSBmcm9tICdtb25nb29zZSc7XG5pbXBvcnQgeyBEQl9DT05OU1RSLCBEQl9OQU1FIH0gZnJvbSAnQC9jb25maWcnO1xuc2V0KCdzdHJpY3RRdWVyeScsIGZhbHNlKTtcbmNsYXNzIERhdGFiYXNlIHtcbiAgICBzdGF0aWMgaW5zdGFuY2UgPSBudWxsO1xuICAgIGNvbnN0cnVjdG9yKCkge1xuICAgICAgICBpZiAoRGF0YWJhc2UuaW5zdGFuY2UgPT09IG51bGwpXG4gICAgICAgICAgICBEYXRhYmFzZS5pbnN0YW5jZSA9IHRoaXM7XG4gICAgICAgIHJldHVybiBEYXRhYmFzZS5pbnN0YW5jZTtcbiAgICB9XG4gICAgaXNDb25uZWN0ZWQgPSAoKSA9PiBjb25uZWN0aW9uLnJlYWR5U3RhdGUgPT09IDE7XG4gICAgY29ubmVjdCA9IGFzeW5jICgpID0+IHtcbiAgICAgICAgY29uc3QgZGVmYXVsdFJldHVybiA9IHRoaXMuaXNDb25uZWN0ZWQ7XG4gICAgICAgIGlmICh0aGlzLmlzQ29ubmVjdGVkKCkpXG4gICAgICAgICAgICByZXR1cm4gZGVmYXVsdFJldHVybjtcbiAgICAgICAgY29uc29sZS5sb2coJ1tEQl0gQ29ubmVjdGluZy4uLicpO1xuICAgICAgICB0cnkge1xuICAgICAgICAgICAgYXdhaXQgY29ubmVjdChEQl9DT05OU1RSKTtcbiAgICAgICAgICAgIGNvbnNvbGUubG9nKGBbREJdIENvbm5lY3RlZCB0byBcIiR7REJfTkFNRX1cImApO1xuICAgICAgICB9XG4gICAgICAgIGNhdGNoIChlcnJvcikge1xuICAgICAgICAgICAgY29uc29sZS5lcnJvcignW0RCXSBDb25uZWN0aW9uIGVycm9yJyk7XG4gICAgICAgICAgICBjb25zb2xlLmVycm9yKGVycm9yKTtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gZGVmYXVsdFJldHVybjtcbiAgICB9O1xufVxuZXhwb3J0IHsgRGF0YWJhc2UgfTtcbiIsImNvbnN0IGxvY2FsZSA9ICd1ay1VQSc7XG5jb25zdCB0aW1lWm9uZSA9ICdFdXJvcGUvS2lldic7XG5leHBvcnQgY29uc3QgZ2V0Q3VycmVudFRpbWVTdHJpbmcgPSAoKSA9PiBuZXcgRGF0ZSgpLnRvTG9jYWxlVGltZVN0cmluZyhsb2NhbGUsIHtcbiAgICB0aW1lWm9uZSxcbiAgICBob3VyOiAnMi1kaWdpdCcsXG4gICAgbWludXRlOiAnMi1kaWdpdCcsXG4gICAgc2Vjb25kOiAnMi1kaWdpdCcsXG59KTtcbmV4cG9ydCBjb25zdCBnZXRDdXJyZW50RGF0ZVN0cmluZyA9ICgpID0+IG5ldyBEYXRlKCkudG9Mb2NhbGVEYXRlU3RyaW5nKGxvY2FsZSwge1xuICAgIHRpbWVab25lLFxuICAgIHdlZWtkYXk6ICdsb25nJyxcbiAgICB5ZWFyOiAnbnVtZXJpYycsXG4gICAgbW9udGg6ICdsb25nJyxcbiAgICBkYXk6ICdudW1lcmljJyxcbiAgICBob3VyOiAnbnVtZXJpYycsXG4gICAgbWludXRlOiAnbnVtZXJpYycsXG59KTtcbiIsImltcG9ydCB7IFBPUlQgfSBmcm9tICdAL2NvbmZpZyc7XG5pbXBvcnQgeyBnZXRDdXJyZW50VGltZVN0cmluZyB9IGZyb20gJ0AvdXRpbHMnO1xuZXhwb3J0IGNvbnN0IG1haW5MaXN0ZW4gPSAoKSA9PiB7XG4gICAgdHJ5IHtcbiAgICAgICAgY29uc29sZS5sb2coYFtTRVJWRVJdIHwgJHtnZXRDdXJyZW50VGltZVN0cmluZygpfSBMaXN0ZW5pbmcgYXQgJHtQT1JUfWApO1xuICAgIH1cbiAgICBjYXRjaCAoZXJyb3IpIHtcbiAgICAgICAgY29uc29sZS5lcnJvcihlcnJvcik7XG4gICAgfVxufTtcbiIsImltcG9ydCB7IHNlcnZlciB9IGZyb20gJy4vc2VydmVyJztcbmltcG9ydCB7IERhdGFiYXNlIH0gZnJvbSAnQC9EYXRhYmFzZSc7XG5pbXBvcnQgeyBtYWluTGlzdGVuIH0gZnJvbSAnQC9hcGkvY29udHJvbGxlcnMnO1xuaW1wb3J0IHsgUE9SVCB9IGZyb20gJ0AvY29uZmlnJztcbmNvbnN0IHN0YXJ0ID0gYXN5bmMgKCkgPT4ge1xuICAgIGNvbnN0IGRhdGFiYXNlID0gbmV3IERhdGFiYXNlKCk7XG4gICAgdm9pZCBzZXJ2ZXIubGlzdGVuKFBPUlQsIG1haW5MaXN0ZW4pO1xuICAgIHZvaWQgZGF0YWJhc2UuY29ubmVjdCgpO1xufTtcbnZvaWQgc3RhcnQoKTtcbiJdLCJuYW1lcyI6WyJTVEFUVVMuSU5URVJOQUxfU0VSVkVSX0VSUk9SIiwiRVJST1IuSU5URVJOQUxfU0VSVkVSIiwiU1RBVFVTLkJBRF9SRVFVRVNUIiwiUm91dGVyIiwiU2NoZW1hIiwibW9kZWxzIiwibW9kZWwiLCJTVEFUVVMuT0siLCJjb25maWciLCJzZXQiLCJjb25uZWN0aW9uIiwiY29ubmVjdCJdLCJtYXBwaW5ncyI6Ijs7Ozs7Ozs7O0FBQUEsTUFBTSw0QkFBNEIsR0FBRyxNQUFNLENBQUMsOEJBQThCLEVBQUM7QUFD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
