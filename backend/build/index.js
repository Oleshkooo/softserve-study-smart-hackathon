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
const UNAUTHORIZED = 401;
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
        console.error(error);
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

const UserSchema = new mongoose.Schema({
    email: {
        type: String,
        required: false,
        default: '',
    },
    password: {
        type: String,
        required: false,
        default: '',
    },
    name: {
        type: String,
        required: false,
        default: '',
    },
    perms: {
        type: String,
        required: true,
    },
    university_id: {
        type: String,
        required: false,
        default: '',
    },
    speciality_id: {
        type: String,
        required: false,
        default: '',
    },
    disciplines: {
        type: [DisciplineSchema],
        required: false,
        default: [],
    },
});
UserSchema.methods.isPasswordCorrect = async function (password) {
    return this.password === password;
};
const UserModel = mongoose.models.User ?? mongoose.model('User', UserSchema);

const post$1 = async (req, res) => {
    try {
        const { email, password } = req.body;
        if (email === undefined || password === undefined) {
            const response = new ApiError({
                status: BAD_REQUEST,
                message: 'Missing required fields',
            });
            return res.status(response.status).send(response);
        }
        const user = await UserModel.findOne({ email });
        const isPasswordCorrect = await (() => {
            if (user === null)
                return false;
            return user.isPasswordCorrect(password);
        })();
        if (!isPasswordCorrect) {
            const response = new ApiError({
                status: UNAUTHORIZED,
                message: 'Email or password is incorrect',
            });
            return res.status(response.status).send(response);
        }
        const response = new ApiSuccess({
            status: OK,
            message: 'Success',
            data: user,
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

const loginRouter = express.Router();
loginRouter.post('/', post$1);

const get$1 = async (req, res) => {
    try {
        const { id, abbr } = req.body;
        const data = await (async () => {
            if (id !== undefined) {
                return await UniversityModel.find({ id }).lean();
            }
            if (abbr !== undefined) {
                return await UniversityModel.find({ abbr }).lean();
            }
            return await UniversityModel.find().lean();
        })();
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
universityRouter.get('/', get$1);

const get = async (req, res) => {
    try {
        const { teacherEmail } = req.body;
        if (teacherEmail === undefined) {
            const response = new ApiError({
                status: BAD_REQUEST,
                message: 'Missing required fields',
            });
            return res.status(response.status).send(response);
        }
        const students = await UserModel.find({
            disciplines: { $elemMatch: { teacherEmail } },
        }).lean();
        const response = new ApiSuccess({
            status: OK,
            message: 'Success',
            data: students,
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

const put = async (req, res) => {
    try {
        const { studentEmail, teacherEmail, labName, rating, message, points } = req.body;
        if (studentEmail === undefined ||
            teacherEmail === undefined ||
            labName === undefined ||
            rating === undefined ||
            message === undefined ||
            points === undefined) {
            const response = new ApiError({
                status: BAD_REQUEST,
                message: 'Missing required fields',
            });
            return res.status(response.status).send(response);
        }
        const updatedStudent = await UserModel.findOneAndUpdate({
            email: studentEmail,
            'disciplines.teacherEmail': teacherEmail,
            'disciplines.labs.name': labName,
        }, {
            $set: {
                'disciplines.$[discipline].labs.$[lab].rating': rating,
                'disciplines.$[discipline].labs.$[lab].message': message,
                'disciplines.$[discipline].labs.$[lab].points': points,
            },
        }, {
            arrayFilters: [
                { 'discipline.teacherEmail': teacherEmail },
                { 'lab.name': labName },
            ],
            new: true,
        });
        const response = new ApiSuccess({
            status: OK,
            message: 'Success',
            data: updatedStudent,
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

const studentRouter = express.Router();
studentRouter.get('/', get);
studentRouter.put('/', put);

const del = async (req, res) => {
    try {
        const { email } = req.body;
        if (email === undefined) {
            const response = new ApiError({
                status: BAD_REQUEST,
                message: 'Missing required fields',
            });
            return res.status(response.status).send(response);
        }
        const found = UserModel.findOne({ email });
        if (found === null || found === undefined) {
            const response = new ApiError({
                status: BAD_REQUEST,
                message: 'User not found',
            });
            return res.status(response.status).send(response);
        }
        await UserModel.deleteOne({ email });
        const response = new ApiSuccess({
            status: OK,
            message: 'User deleted',
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

const post = async (req, res) => {
    try {
        const { email, password, name, universityId, specialityId, perms } = req.body;
        if (email === undefined ||
            password === undefined ||
            name === undefined ||
            universityId === undefined ||
            specialityId === undefined ||
            perms === undefined) {
            const response = new ApiError({
                status: BAD_REQUEST,
                message: 'Missing required fields',
            });
            return res.status(response.status).send(response);
        }
        const userExists = await UserModel.exists({ email });
        if (userExists) {
            const response = new ApiError({
                status: BAD_REQUEST,
                message: 'Email already in use',
            });
            return res.status(response.status).send(response);
        }
        const user = await UserModel.create({
            email,
            password,
            name,
            perms,
            university_id: universityId,
            speciality_id: specialityId,
        });
        const validationError = user.validateSync();
        if (validationError !== undefined) {
            const response = new ApiError({
                status: BAD_REQUEST,
                message: 'Validation error',
            });
            return res.status(response.status).send(response);
        }
        await user.save();
        const response = {
            status: OK,
            message: 'User created',
            data: user,
        };
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

const adminRouter = express.Router();
adminRouter.post('/user', post);
adminRouter.delete('/user', del);

const apiRouter = express.Router();
apiRouter.use('/university', universityRouter);
apiRouter.use('/login', loginRouter);
apiRouter.use('/student', studentRouter);
apiRouter.use('/admin', adminRouter);

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
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXguanMiLCJzb3VyY2VzIjpbIi4uL25vZGVfbW9kdWxlcy8ucG5wbS9oZWxtZXRANi4xLjUvbm9kZV9tb2R1bGVzL2hlbG1ldC9pbmRleC5tanMiLCIuLi9zcmMvYXBpL3Jlc3BvbnNlcy9lcnJvck1lc3NhZ2VzLnRzIiwiLi4vc3JjL2FwaS9yZXNwb25zZXMvc3RhdHVzQ29kZXMudHMiLCIuLi9zcmMvYXBpL3Jlc3BvbnNlcy9BcGlFcnJvci50cyIsIi4uL3NyYy9hcGkvcmVzcG9uc2VzL0FwaVN1Y2Nlc3MudHMiLCIuLi9zcmMvRGF0YWJhc2UvbW9kZWxzL1VuaXZlcnNpdHkudHMiLCIuLi9zcmMvRGF0YWJhc2UvbW9kZWxzL1VzZXIudHMiLCIuLi9zcmMvYXBpL2NvbnRyb2xsZXJzL2xvZ2luL3Bvc3QudHMiLCIuLi9zcmMvYXBpL3JvdXRlcy9sb2dpblJvdXRlci50cyIsIi4uL3NyYy9hcGkvY29udHJvbGxlcnMvdW5pdmVyc2l0eS9nZXQudHMiLCIuLi9zcmMvYXBpL3JvdXRlcy91bml2ZXJzaXR5Um91dGVyLnRzIiwiLi4vc3JjL2FwaS9jb250cm9sbGVycy9zdHVkZW50L2dldC50cyIsIi4uL3NyYy9hcGkvY29udHJvbGxlcnMvc3R1ZGVudC9wdXQudHMiLCIuLi9zcmMvYXBpL3JvdXRlcy9zdHVkZW50Um91dGVyLnRzIiwiLi4vc3JjL2FwaS9jb250cm9sbGVycy9hZG1pbi9kZWwudHMiLCIuLi9zcmMvYXBpL2NvbnRyb2xsZXJzL2FkbWluL3Bvc3QudHMiLCIuLi9zcmMvYXBpL3JvdXRlcy9hZG1pblJvdXRlci50cyIsIi4uL3NyYy9hcGkvYXBpUm91dGVyLnRzIiwiLi4vc3JjL3NlcnZlci50cyIsIi4uL3NyYy9jb25maWcudHMiLCIuLi9zcmMvRGF0YWJhc2UvRGF0YWJhc2UudHMiLCIuLi9zcmMvdXRpbHMvZGF0ZS50cyIsIi4uL3NyYy9hcGkvY29udHJvbGxlcnMvbWFpbi9tYWluTGlzdGVuLnRzIiwiLi4vc3JjL2luZGV4LnRzIl0sInNvdXJjZXNDb250ZW50IjpbImNvbnN0IGRhbmdlcm91c2x5RGlzYWJsZURlZmF1bHRTcmMgPSBTeW1ib2woXCJkYW5nZXJvdXNseURpc2FibGVEZWZhdWx0U3JjXCIpXG5jb25zdCBERUZBVUxUX0RJUkVDVElWRVMgPSB7XG5cdFwiZGVmYXVsdC1zcmNcIjogW1wiJ3NlbGYnXCJdLFxuXHRcImJhc2UtdXJpXCI6IFtcIidzZWxmJ1wiXSxcblx0XCJmb250LXNyY1wiOiBbXCInc2VsZidcIiwgXCJodHRwczpcIiwgXCJkYXRhOlwiXSxcblx0XCJmb3JtLWFjdGlvblwiOiBbXCInc2VsZidcIl0sXG5cdFwiZnJhbWUtYW5jZXN0b3JzXCI6IFtcIidzZWxmJ1wiXSxcblx0XCJpbWctc3JjXCI6IFtcIidzZWxmJ1wiLCBcImRhdGE6XCJdLFxuXHRcIm9iamVjdC1zcmNcIjogW1wiJ25vbmUnXCJdLFxuXHRcInNjcmlwdC1zcmNcIjogW1wiJ3NlbGYnXCJdLFxuXHRcInNjcmlwdC1zcmMtYXR0clwiOiBbXCInbm9uZSdcIl0sXG5cdFwic3R5bGUtc3JjXCI6IFtcIidzZWxmJ1wiLCBcImh0dHBzOlwiLCBcIid1bnNhZmUtaW5saW5lJ1wiXSxcblx0XCJ1cGdyYWRlLWluc2VjdXJlLXJlcXVlc3RzXCI6IFtdXG59XG5jb25zdCBnZXREZWZhdWx0RGlyZWN0aXZlcyA9ICgpID0+IE9iamVjdC5hc3NpZ24oe30sIERFRkFVTFRfRElSRUNUSVZFUylcbmNvbnN0IGRhc2hpZnkgPSBzdHIgPT4gc3RyLnJlcGxhY2UoL1tBLVpdL2csIGNhcGl0YWxMZXR0ZXIgPT4gXCItXCIgKyBjYXBpdGFsTGV0dGVyLnRvTG93ZXJDYXNlKCkpXG5jb25zdCBpc0RpcmVjdGl2ZVZhbHVlSW52YWxpZCA9IGRpcmVjdGl2ZVZhbHVlID0+IC87fCwvLnRlc3QoZGlyZWN0aXZlVmFsdWUpXG5jb25zdCBoYXMgPSAob2JqLCBrZXkpID0+IE9iamVjdC5wcm90b3R5cGUuaGFzT3duUHJvcGVydHkuY2FsbChvYmosIGtleSlcbmZ1bmN0aW9uIG5vcm1hbGl6ZURpcmVjdGl2ZXMob3B0aW9ucykge1xuXHRjb25zdCBkZWZhdWx0RGlyZWN0aXZlcyA9IGdldERlZmF1bHREaXJlY3RpdmVzKClcblx0Y29uc3Qge3VzZURlZmF1bHRzID0gdHJ1ZSwgZGlyZWN0aXZlczogcmF3RGlyZWN0aXZlcyA9IGRlZmF1bHREaXJlY3RpdmVzfSA9IG9wdGlvbnNcblx0Y29uc3QgcmVzdWx0ID0gbmV3IE1hcCgpXG5cdGNvbnN0IGRpcmVjdGl2ZU5hbWVzU2VlbiA9IG5ldyBTZXQoKVxuXHRjb25zdCBkaXJlY3RpdmVzRXhwbGljaXRseURpc2FibGVkID0gbmV3IFNldCgpXG5cdGZvciAoY29uc3QgcmF3RGlyZWN0aXZlTmFtZSBpbiByYXdEaXJlY3RpdmVzKSB7XG5cdFx0aWYgKCFoYXMocmF3RGlyZWN0aXZlcywgcmF3RGlyZWN0aXZlTmFtZSkpIHtcblx0XHRcdGNvbnRpbnVlXG5cdFx0fVxuXHRcdGlmIChyYXdEaXJlY3RpdmVOYW1lLmxlbmd0aCA9PT0gMCB8fCAvW15hLXpBLVowLTktXS8udGVzdChyYXdEaXJlY3RpdmVOYW1lKSkge1xuXHRcdFx0dGhyb3cgbmV3IEVycm9yKGBDb250ZW50LVNlY3VyaXR5LVBvbGljeSByZWNlaXZlZCBhbiBpbnZhbGlkIGRpcmVjdGl2ZSBuYW1lICR7SlNPTi5zdHJpbmdpZnkocmF3RGlyZWN0aXZlTmFtZSl9YClcblx0XHR9XG5cdFx0Y29uc3QgZGlyZWN0aXZlTmFtZSA9IGRhc2hpZnkocmF3RGlyZWN0aXZlTmFtZSlcblx0XHRpZiAoZGlyZWN0aXZlTmFtZXNTZWVuLmhhcyhkaXJlY3RpdmVOYW1lKSkge1xuXHRcdFx0dGhyb3cgbmV3IEVycm9yKGBDb250ZW50LVNlY3VyaXR5LVBvbGljeSByZWNlaXZlZCBhIGR1cGxpY2F0ZSBkaXJlY3RpdmUgJHtKU09OLnN0cmluZ2lmeShkaXJlY3RpdmVOYW1lKX1gKVxuXHRcdH1cblx0XHRkaXJlY3RpdmVOYW1lc1NlZW4uYWRkKGRpcmVjdGl2ZU5hbWUpXG5cdFx0Y29uc3QgcmF3RGlyZWN0aXZlVmFsdWUgPSByYXdEaXJlY3RpdmVzW3Jhd0RpcmVjdGl2ZU5hbWVdXG5cdFx0bGV0IGRpcmVjdGl2ZVZhbHVlXG5cdFx0aWYgKHJhd0RpcmVjdGl2ZVZhbHVlID09PSBudWxsKSB7XG5cdFx0XHRpZiAoZGlyZWN0aXZlTmFtZSA9PT0gXCJkZWZhdWx0LXNyY1wiKSB7XG5cdFx0XHRcdHRocm93IG5ldyBFcnJvcihcIkNvbnRlbnQtU2VjdXJpdHktUG9saWN5IG5lZWRzIGEgZGVmYXVsdC1zcmMgYnV0IGl0IHdhcyBzZXQgdG8gYG51bGxgLiBJZiB5b3UgcmVhbGx5IHdhbnQgdG8gZGlzYWJsZSBpdCwgc2V0IGl0IHRvIGBjb250ZW50U2VjdXJpdHlQb2xpY3kuZGFuZ2Vyb3VzbHlEaXNhYmxlRGVmYXVsdFNyY2AuXCIpXG5cdFx0XHR9XG5cdFx0XHRkaXJlY3RpdmVzRXhwbGljaXRseURpc2FibGVkLmFkZChkaXJlY3RpdmVOYW1lKVxuXHRcdFx0Y29udGludWVcblx0XHR9IGVsc2UgaWYgKHR5cGVvZiByYXdEaXJlY3RpdmVWYWx1ZSA9PT0gXCJzdHJpbmdcIikge1xuXHRcdFx0ZGlyZWN0aXZlVmFsdWUgPSBbcmF3RGlyZWN0aXZlVmFsdWVdXG5cdFx0fSBlbHNlIGlmICghcmF3RGlyZWN0aXZlVmFsdWUpIHtcblx0XHRcdHRocm93IG5ldyBFcnJvcihgQ29udGVudC1TZWN1cml0eS1Qb2xpY3kgcmVjZWl2ZWQgYW4gaW52YWxpZCBkaXJlY3RpdmUgdmFsdWUgZm9yICR7SlNPTi5zdHJpbmdpZnkoZGlyZWN0aXZlTmFtZSl9YClcblx0XHR9IGVsc2UgaWYgKHJhd0RpcmVjdGl2ZVZhbHVlID09PSBkYW5nZXJvdXNseURpc2FibGVEZWZhdWx0U3JjKSB7XG5cdFx0XHRpZiAoZGlyZWN0aXZlTmFtZSA9PT0gXCJkZWZhdWx0LXNyY1wiKSB7XG5cdFx0XHRcdGRpcmVjdGl2ZXNFeHBsaWNpdGx5RGlzYWJsZWQuYWRkKFwiZGVmYXVsdC1zcmNcIilcblx0XHRcdFx0Y29udGludWVcblx0XHRcdH0gZWxzZSB7XG5cdFx0XHRcdHRocm93IG5ldyBFcnJvcihgQ29udGVudC1TZWN1cml0eS1Qb2xpY3k6IHRyaWVkIHRvIGRpc2FibGUgJHtKU09OLnN0cmluZ2lmeShkaXJlY3RpdmVOYW1lKX0gYXMgaWYgaXQgd2VyZSBkZWZhdWx0LXNyYzsgc2ltcGx5IG9taXQgdGhlIGtleWApXG5cdFx0XHR9XG5cdFx0fSBlbHNlIHtcblx0XHRcdGRpcmVjdGl2ZVZhbHVlID0gcmF3RGlyZWN0aXZlVmFsdWVcblx0XHR9XG5cdFx0Zm9yIChjb25zdCBlbGVtZW50IG9mIGRpcmVjdGl2ZVZhbHVlKSB7XG5cdFx0XHRpZiAodHlwZW9mIGVsZW1lbnQgPT09IFwic3RyaW5nXCIgJiYgaXNEaXJlY3RpdmVWYWx1ZUludmFsaWQoZWxlbWVudCkpIHtcblx0XHRcdFx0dGhyb3cgbmV3IEVycm9yKGBDb250ZW50LVNlY3VyaXR5LVBvbGljeSByZWNlaXZlZCBhbiBpbnZhbGlkIGRpcmVjdGl2ZSB2YWx1ZSBmb3IgJHtKU09OLnN0cmluZ2lmeShkaXJlY3RpdmVOYW1lKX1gKVxuXHRcdFx0fVxuXHRcdH1cblx0XHRyZXN1bHQuc2V0KGRpcmVjdGl2ZU5hbWUsIGRpcmVjdGl2ZVZhbHVlKVxuXHR9XG5cdGlmICh1c2VEZWZhdWx0cykge1xuXHRcdE9iamVjdC5lbnRyaWVzKGRlZmF1bHREaXJlY3RpdmVzKS5mb3JFYWNoKChbZGVmYXVsdERpcmVjdGl2ZU5hbWUsIGRlZmF1bHREaXJlY3RpdmVWYWx1ZV0pID0+IHtcblx0XHRcdGlmICghcmVzdWx0LmhhcyhkZWZhdWx0RGlyZWN0aXZlTmFtZSkgJiYgIWRpcmVjdGl2ZXNFeHBsaWNpdGx5RGlzYWJsZWQuaGFzKGRlZmF1bHREaXJlY3RpdmVOYW1lKSkge1xuXHRcdFx0XHRyZXN1bHQuc2V0KGRlZmF1bHREaXJlY3RpdmVOYW1lLCBkZWZhdWx0RGlyZWN0aXZlVmFsdWUpXG5cdFx0XHR9XG5cdFx0fSlcblx0fVxuXHRpZiAoIXJlc3VsdC5zaXplKSB7XG5cdFx0dGhyb3cgbmV3IEVycm9yKFwiQ29udGVudC1TZWN1cml0eS1Qb2xpY3kgaGFzIG5vIGRpcmVjdGl2ZXMuIEVpdGhlciBzZXQgc29tZSBvciBkaXNhYmxlIHRoZSBoZWFkZXJcIilcblx0fVxuXHRpZiAoIXJlc3VsdC5oYXMoXCJkZWZhdWx0LXNyY1wiKSAmJiAhZGlyZWN0aXZlc0V4cGxpY2l0bHlEaXNhYmxlZC5oYXMoXCJkZWZhdWx0LXNyY1wiKSkge1xuXHRcdHRocm93IG5ldyBFcnJvcihcIkNvbnRlbnQtU2VjdXJpdHktUG9saWN5IG5lZWRzIGEgZGVmYXVsdC1zcmMgYnV0IG5vbmUgd2FzIHByb3ZpZGVkLiBJZiB5b3UgcmVhbGx5IHdhbnQgdG8gZGlzYWJsZSBpdCwgc2V0IGl0IHRvIGBjb250ZW50U2VjdXJpdHlQb2xpY3kuZGFuZ2Vyb3VzbHlEaXNhYmxlRGVmYXVsdFNyY2AuXCIpXG5cdH1cblx0cmV0dXJuIHJlc3VsdFxufVxuZnVuY3Rpb24gZ2V0SGVhZGVyVmFsdWUocmVxLCByZXMsIG5vcm1hbGl6ZWREaXJlY3RpdmVzKSB7XG5cdGxldCBlcnJcblx0Y29uc3QgcmVzdWx0ID0gW11cblx0bm9ybWFsaXplZERpcmVjdGl2ZXMuZm9yRWFjaCgocmF3RGlyZWN0aXZlVmFsdWUsIGRpcmVjdGl2ZU5hbWUpID0+IHtcblx0XHRsZXQgZGlyZWN0aXZlVmFsdWUgPSBcIlwiXG5cdFx0Zm9yIChjb25zdCBlbGVtZW50IG9mIHJhd0RpcmVjdGl2ZVZhbHVlKSB7XG5cdFx0XHRkaXJlY3RpdmVWYWx1ZSArPSBcIiBcIiArIChlbGVtZW50IGluc3RhbmNlb2YgRnVuY3Rpb24gPyBlbGVtZW50KHJlcSwgcmVzKSA6IGVsZW1lbnQpXG5cdFx0fVxuXHRcdGlmICghZGlyZWN0aXZlVmFsdWUpIHtcblx0XHRcdHJlc3VsdC5wdXNoKGRpcmVjdGl2ZU5hbWUpXG5cdFx0fSBlbHNlIGlmIChpc0RpcmVjdGl2ZVZhbHVlSW52YWxpZChkaXJlY3RpdmVWYWx1ZSkpIHtcblx0XHRcdGVyciA9IG5ldyBFcnJvcihgQ29udGVudC1TZWN1cml0eS1Qb2xpY3kgcmVjZWl2ZWQgYW4gaW52YWxpZCBkaXJlY3RpdmUgdmFsdWUgZm9yICR7SlNPTi5zdHJpbmdpZnkoZGlyZWN0aXZlTmFtZSl9YClcblx0XHR9IGVsc2Uge1xuXHRcdFx0cmVzdWx0LnB1c2goYCR7ZGlyZWN0aXZlTmFtZX0ke2RpcmVjdGl2ZVZhbHVlfWApXG5cdFx0fVxuXHR9KVxuXHRyZXR1cm4gZXJyID8gZXJyIDogcmVzdWx0LmpvaW4oXCI7XCIpXG59XG5jb25zdCBjb250ZW50U2VjdXJpdHlQb2xpY3kgPSBmdW5jdGlvbiBjb250ZW50U2VjdXJpdHlQb2xpY3kob3B0aW9ucyA9IHt9KSB7XG5cdGNvbnN0IGhlYWRlck5hbWUgPSBvcHRpb25zLnJlcG9ydE9ubHkgPyBcIkNvbnRlbnQtU2VjdXJpdHktUG9saWN5LVJlcG9ydC1Pbmx5XCIgOiBcIkNvbnRlbnQtU2VjdXJpdHktUG9saWN5XCJcblx0Y29uc3Qgbm9ybWFsaXplZERpcmVjdGl2ZXMgPSBub3JtYWxpemVEaXJlY3RpdmVzKG9wdGlvbnMpXG5cdHJldHVybiBmdW5jdGlvbiBjb250ZW50U2VjdXJpdHlQb2xpY3lNaWRkbGV3YXJlKHJlcSwgcmVzLCBuZXh0KSB7XG5cdFx0Y29uc3QgcmVzdWx0ID0gZ2V0SGVhZGVyVmFsdWUocmVxLCByZXMsIG5vcm1hbGl6ZWREaXJlY3RpdmVzKVxuXHRcdGlmIChyZXN1bHQgaW5zdGFuY2VvZiBFcnJvcikge1xuXHRcdFx0bmV4dChyZXN1bHQpXG5cdFx0fSBlbHNlIHtcblx0XHRcdHJlcy5zZXRIZWFkZXIoaGVhZGVyTmFtZSwgcmVzdWx0KVxuXHRcdFx0bmV4dCgpXG5cdFx0fVxuXHR9XG59XG5jb250ZW50U2VjdXJpdHlQb2xpY3kuZ2V0RGVmYXVsdERpcmVjdGl2ZXMgPSBnZXREZWZhdWx0RGlyZWN0aXZlc1xuY29udGVudFNlY3VyaXR5UG9saWN5LmRhbmdlcm91c2x5RGlzYWJsZURlZmF1bHRTcmMgPSBkYW5nZXJvdXNseURpc2FibGVEZWZhdWx0U3JjXG5cbmNvbnN0IEFMTE9XRURfUE9MSUNJRVMkMiA9IG5ldyBTZXQoW1wicmVxdWlyZS1jb3JwXCIsIFwiY3JlZGVudGlhbGxlc3NcIl0pXG5mdW5jdGlvbiBnZXRIZWFkZXJWYWx1ZUZyb21PcHRpb25zJDcoe3BvbGljeSA9IFwicmVxdWlyZS1jb3JwXCJ9KSB7XG5cdGlmIChBTExPV0VEX1BPTElDSUVTJDIuaGFzKHBvbGljeSkpIHtcblx0XHRyZXR1cm4gcG9saWN5XG5cdH0gZWxzZSB7XG5cdFx0dGhyb3cgbmV3IEVycm9yKGBDcm9zcy1PcmlnaW4tRW1iZWRkZXItUG9saWN5IGRvZXMgbm90IHN1cHBvcnQgdGhlICR7SlNPTi5zdHJpbmdpZnkocG9saWN5KX0gcG9saWN5YClcblx0fVxufVxuZnVuY3Rpb24gY3Jvc3NPcmlnaW5FbWJlZGRlclBvbGljeShvcHRpb25zID0ge30pIHtcblx0Y29uc3QgaGVhZGVyVmFsdWUgPSBnZXRIZWFkZXJWYWx1ZUZyb21PcHRpb25zJDcob3B0aW9ucylcblx0cmV0dXJuIGZ1bmN0aW9uIGNyb3NzT3JpZ2luRW1iZWRkZXJQb2xpY3lNaWRkbGV3YXJlKF9yZXEsIHJlcywgbmV4dCkge1xuXHRcdHJlcy5zZXRIZWFkZXIoXCJDcm9zcy1PcmlnaW4tRW1iZWRkZXItUG9saWN5XCIsIGhlYWRlclZhbHVlKVxuXHRcdG5leHQoKVxuXHR9XG59XG5cbmNvbnN0IEFMTE9XRURfUE9MSUNJRVMkMSA9IG5ldyBTZXQoW1wic2FtZS1vcmlnaW5cIiwgXCJzYW1lLW9yaWdpbi1hbGxvdy1wb3B1cHNcIiwgXCJ1bnNhZmUtbm9uZVwiXSlcbmZ1bmN0aW9uIGdldEhlYWRlclZhbHVlRnJvbU9wdGlvbnMkNih7cG9saWN5ID0gXCJzYW1lLW9yaWdpblwifSkge1xuXHRpZiAoQUxMT1dFRF9QT0xJQ0lFUyQxLmhhcyhwb2xpY3kpKSB7XG5cdFx0cmV0dXJuIHBvbGljeVxuXHR9IGVsc2Uge1xuXHRcdHRocm93IG5ldyBFcnJvcihgQ3Jvc3MtT3JpZ2luLU9wZW5lci1Qb2xpY3kgZG9lcyBub3Qgc3VwcG9ydCB0aGUgJHtKU09OLnN0cmluZ2lmeShwb2xpY3kpfSBwb2xpY3lgKVxuXHR9XG59XG5mdW5jdGlvbiBjcm9zc09yaWdpbk9wZW5lclBvbGljeShvcHRpb25zID0ge30pIHtcblx0Y29uc3QgaGVhZGVyVmFsdWUgPSBnZXRIZWFkZXJWYWx1ZUZyb21PcHRpb25zJDYob3B0aW9ucylcblx0cmV0dXJuIGZ1bmN0aW9uIGNyb3NzT3JpZ2luT3BlbmVyUG9saWN5TWlkZGxld2FyZShfcmVxLCByZXMsIG5leHQpIHtcblx0XHRyZXMuc2V0SGVhZGVyKFwiQ3Jvc3MtT3JpZ2luLU9wZW5lci1Qb2xpY3lcIiwgaGVhZGVyVmFsdWUpXG5cdFx0bmV4dCgpXG5cdH1cbn1cblxuY29uc3QgQUxMT1dFRF9QT0xJQ0lFUyA9IG5ldyBTZXQoW1wic2FtZS1vcmlnaW5cIiwgXCJzYW1lLXNpdGVcIiwgXCJjcm9zcy1vcmlnaW5cIl0pXG5mdW5jdGlvbiBnZXRIZWFkZXJWYWx1ZUZyb21PcHRpb25zJDUoe3BvbGljeSA9IFwic2FtZS1vcmlnaW5cIn0pIHtcblx0aWYgKEFMTE9XRURfUE9MSUNJRVMuaGFzKHBvbGljeSkpIHtcblx0XHRyZXR1cm4gcG9saWN5XG5cdH0gZWxzZSB7XG5cdFx0dGhyb3cgbmV3IEVycm9yKGBDcm9zcy1PcmlnaW4tUmVzb3VyY2UtUG9saWN5IGRvZXMgbm90IHN1cHBvcnQgdGhlICR7SlNPTi5zdHJpbmdpZnkocG9saWN5KX0gcG9saWN5YClcblx0fVxufVxuZnVuY3Rpb24gY3Jvc3NPcmlnaW5SZXNvdXJjZVBvbGljeShvcHRpb25zID0ge30pIHtcblx0Y29uc3QgaGVhZGVyVmFsdWUgPSBnZXRIZWFkZXJWYWx1ZUZyb21PcHRpb25zJDUob3B0aW9ucylcblx0cmV0dXJuIGZ1bmN0aW9uIGNyb3NzT3JpZ2luUmVzb3VyY2VQb2xpY3lNaWRkbGV3YXJlKF9yZXEsIHJlcywgbmV4dCkge1xuXHRcdHJlcy5zZXRIZWFkZXIoXCJDcm9zcy1PcmlnaW4tUmVzb3VyY2UtUG9saWN5XCIsIGhlYWRlclZhbHVlKVxuXHRcdG5leHQoKVxuXHR9XG59XG5cbmZ1bmN0aW9uIHBhcnNlTWF4QWdlJDEodmFsdWUgPSAwKSB7XG5cdGlmICh2YWx1ZSA+PSAwICYmIE51bWJlci5pc0Zpbml0ZSh2YWx1ZSkpIHtcblx0XHRyZXR1cm4gTWF0aC5mbG9vcih2YWx1ZSlcblx0fSBlbHNlIHtcblx0XHR0aHJvdyBuZXcgRXJyb3IoYEV4cGVjdC1DVDogJHtKU09OLnN0cmluZ2lmeSh2YWx1ZSl9IGlzIG5vdCBhIHZhbGlkIHZhbHVlIGZvciBtYXhBZ2UuIFBsZWFzZSBjaG9vc2UgYSBwb3NpdGl2ZSBpbnRlZ2VyLmApXG5cdH1cbn1cbmZ1bmN0aW9uIGdldEhlYWRlclZhbHVlRnJvbU9wdGlvbnMkNChvcHRpb25zKSB7XG5cdGNvbnN0IGRpcmVjdGl2ZXMgPSBbYG1heC1hZ2U9JHtwYXJzZU1heEFnZSQxKG9wdGlvbnMubWF4QWdlKX1gXVxuXHRpZiAob3B0aW9ucy5lbmZvcmNlKSB7XG5cdFx0ZGlyZWN0aXZlcy5wdXNoKFwiZW5mb3JjZVwiKVxuXHR9XG5cdGlmIChvcHRpb25zLnJlcG9ydFVyaSkge1xuXHRcdGRpcmVjdGl2ZXMucHVzaChgcmVwb3J0LXVyaT1cIiR7b3B0aW9ucy5yZXBvcnRVcml9XCJgKVxuXHR9XG5cdHJldHVybiBkaXJlY3RpdmVzLmpvaW4oXCIsIFwiKVxufVxuZnVuY3Rpb24gZXhwZWN0Q3Qob3B0aW9ucyA9IHt9KSB7XG5cdGNvbnN0IGhlYWRlclZhbHVlID0gZ2V0SGVhZGVyVmFsdWVGcm9tT3B0aW9ucyQ0KG9wdGlvbnMpXG5cdHJldHVybiBmdW5jdGlvbiBleHBlY3RDdE1pZGRsZXdhcmUoX3JlcSwgcmVzLCBuZXh0KSB7XG5cdFx0cmVzLnNldEhlYWRlcihcIkV4cGVjdC1DVFwiLCBoZWFkZXJWYWx1ZSlcblx0XHRuZXh0KClcblx0fVxufVxuXG5mdW5jdGlvbiBvcmlnaW5BZ2VudENsdXN0ZXIoKSB7XG5cdHJldHVybiBmdW5jdGlvbiBvcmlnaW5BZ2VudENsdXN0ZXJNaWRkbGV3YXJlKF9yZXEsIHJlcywgbmV4dCkge1xuXHRcdHJlcy5zZXRIZWFkZXIoXCJPcmlnaW4tQWdlbnQtQ2x1c3RlclwiLCBcIj8xXCIpXG5cdFx0bmV4dCgpXG5cdH1cbn1cblxuY29uc3QgQUxMT1dFRF9UT0tFTlMgPSBuZXcgU2V0KFtcIm5vLXJlZmVycmVyXCIsIFwibm8tcmVmZXJyZXItd2hlbi1kb3duZ3JhZGVcIiwgXCJzYW1lLW9yaWdpblwiLCBcIm9yaWdpblwiLCBcInN0cmljdC1vcmlnaW5cIiwgXCJvcmlnaW4td2hlbi1jcm9zcy1vcmlnaW5cIiwgXCJzdHJpY3Qtb3JpZ2luLXdoZW4tY3Jvc3Mtb3JpZ2luXCIsIFwidW5zYWZlLXVybFwiLCBcIlwiXSlcbmZ1bmN0aW9uIGdldEhlYWRlclZhbHVlRnJvbU9wdGlvbnMkMyh7cG9saWN5ID0gW1wibm8tcmVmZXJyZXJcIl19KSB7XG5cdGNvbnN0IHRva2VucyA9IHR5cGVvZiBwb2xpY3kgPT09IFwic3RyaW5nXCIgPyBbcG9saWN5XSA6IHBvbGljeVxuXHRpZiAodG9rZW5zLmxlbmd0aCA9PT0gMCkge1xuXHRcdHRocm93IG5ldyBFcnJvcihcIlJlZmVycmVyLVBvbGljeSByZWNlaXZlZCBubyBwb2xpY3kgdG9rZW5zXCIpXG5cdH1cblx0Y29uc3QgdG9rZW5zU2VlbiA9IG5ldyBTZXQoKVxuXHR0b2tlbnMuZm9yRWFjaCh0b2tlbiA9PiB7XG5cdFx0aWYgKCFBTExPV0VEX1RPS0VOUy5oYXModG9rZW4pKSB7XG5cdFx0XHR0aHJvdyBuZXcgRXJyb3IoYFJlZmVycmVyLVBvbGljeSByZWNlaXZlZCBhbiB1bmV4cGVjdGVkIHBvbGljeSB0b2tlbiAke0pTT04uc3RyaW5naWZ5KHRva2VuKX1gKVxuXHRcdH0gZWxzZSBpZiAodG9rZW5zU2Vlbi5oYXModG9rZW4pKSB7XG5cdFx0XHR0aHJvdyBuZXcgRXJyb3IoYFJlZmVycmVyLVBvbGljeSByZWNlaXZlZCBhIGR1cGxpY2F0ZSBwb2xpY3kgdG9rZW4gJHtKU09OLnN0cmluZ2lmeSh0b2tlbil9YClcblx0XHR9XG5cdFx0dG9rZW5zU2Vlbi5hZGQodG9rZW4pXG5cdH0pXG5cdHJldHVybiB0b2tlbnMuam9pbihcIixcIilcbn1cbmZ1bmN0aW9uIHJlZmVycmVyUG9saWN5KG9wdGlvbnMgPSB7fSkge1xuXHRjb25zdCBoZWFkZXJWYWx1ZSA9IGdldEhlYWRlclZhbHVlRnJvbU9wdGlvbnMkMyhvcHRpb25zKVxuXHRyZXR1cm4gZnVuY3Rpb24gcmVmZXJyZXJQb2xpY3lNaWRkbGV3YXJlKF9yZXEsIHJlcywgbmV4dCkge1xuXHRcdHJlcy5zZXRIZWFkZXIoXCJSZWZlcnJlci1Qb2xpY3lcIiwgaGVhZGVyVmFsdWUpXG5cdFx0bmV4dCgpXG5cdH1cbn1cblxuY29uc3QgREVGQVVMVF9NQVhfQUdFID0gMTgwICogMjQgKiA2MCAqIDYwXG5mdW5jdGlvbiBwYXJzZU1heEFnZSh2YWx1ZSA9IERFRkFVTFRfTUFYX0FHRSkge1xuXHRpZiAodmFsdWUgPj0gMCAmJiBOdW1iZXIuaXNGaW5pdGUodmFsdWUpKSB7XG5cdFx0cmV0dXJuIE1hdGguZmxvb3IodmFsdWUpXG5cdH0gZWxzZSB7XG5cdFx0dGhyb3cgbmV3IEVycm9yKGBTdHJpY3QtVHJhbnNwb3J0LVNlY3VyaXR5OiAke0pTT04uc3RyaW5naWZ5KHZhbHVlKX0gaXMgbm90IGEgdmFsaWQgdmFsdWUgZm9yIG1heEFnZS4gUGxlYXNlIGNob29zZSBhIHBvc2l0aXZlIGludGVnZXIuYClcblx0fVxufVxuZnVuY3Rpb24gZ2V0SGVhZGVyVmFsdWVGcm9tT3B0aW9ucyQyKG9wdGlvbnMpIHtcblx0aWYgKFwibWF4YWdlXCIgaW4gb3B0aW9ucykge1xuXHRcdHRocm93IG5ldyBFcnJvcihcIlN0cmljdC1UcmFuc3BvcnQtU2VjdXJpdHkgcmVjZWl2ZWQgYW4gdW5zdXBwb3J0ZWQgcHJvcGVydHksIGBtYXhhZ2VgLiBEaWQgeW91IG1lYW4gdG8gcGFzcyBgbWF4QWdlYD9cIilcblx0fVxuXHRpZiAoXCJpbmNsdWRlU3ViZG9tYWluc1wiIGluIG9wdGlvbnMpIHtcblx0XHRjb25zb2xlLndhcm4oJ1N0cmljdC1UcmFuc3BvcnQtU2VjdXJpdHkgbWlkZGxld2FyZSBzaG91bGQgdXNlIGBpbmNsdWRlU3ViRG9tYWluc2AgaW5zdGVhZCBvZiBgaW5jbHVkZVN1YmRvbWFpbnNgLiAoVGhlIGNvcnJlY3Qgb25lIGhhcyBhbiB1cHBlcmNhc2UgXCJEXCIuKScpXG5cdH1cblx0aWYgKFwic2V0SWZcIiBpbiBvcHRpb25zKSB7XG5cdFx0Y29uc29sZS53YXJuKFwiU3RyaWN0LVRyYW5zcG9ydC1TZWN1cml0eSBtaWRkbGV3YXJlIG5vIGxvbmdlciBzdXBwb3J0cyB0aGUgYHNldElmYCBwYXJhbWV0ZXIuIFNlZSB0aGUgZG9jdW1lbnRhdGlvbiBhbmQgPGh0dHBzOi8vZ2l0aHViLmNvbS9oZWxtZXRqcy9oZWxtZXQvd2lraS9Db25kaXRpb25hbGx5LXVzaW5nLW1pZGRsZXdhcmU+IGlmIHlvdSBuZWVkIGhlbHAgcmVwbGljYXRpbmcgdGhpcyBiZWhhdmlvci5cIilcblx0fVxuXHRjb25zdCBkaXJlY3RpdmVzID0gW2BtYXgtYWdlPSR7cGFyc2VNYXhBZ2Uob3B0aW9ucy5tYXhBZ2UpfWBdXG5cdGlmIChvcHRpb25zLmluY2x1ZGVTdWJEb21haW5zID09PSB1bmRlZmluZWQgfHwgb3B0aW9ucy5pbmNsdWRlU3ViRG9tYWlucykge1xuXHRcdGRpcmVjdGl2ZXMucHVzaChcImluY2x1ZGVTdWJEb21haW5zXCIpXG5cdH1cblx0aWYgKG9wdGlvbnMucHJlbG9hZCkge1xuXHRcdGRpcmVjdGl2ZXMucHVzaChcInByZWxvYWRcIilcblx0fVxuXHRyZXR1cm4gZGlyZWN0aXZlcy5qb2luKFwiOyBcIilcbn1cbmZ1bmN0aW9uIHN0cmljdFRyYW5zcG9ydFNlY3VyaXR5KG9wdGlvbnMgPSB7fSkge1xuXHRjb25zdCBoZWFkZXJWYWx1ZSA9IGdldEhlYWRlclZhbHVlRnJvbU9wdGlvbnMkMihvcHRpb25zKVxuXHRyZXR1cm4gZnVuY3Rpb24gc3RyaWN0VHJhbnNwb3J0U2VjdXJpdHlNaWRkbGV3YXJlKF9yZXEsIHJlcywgbmV4dCkge1xuXHRcdHJlcy5zZXRIZWFkZXIoXCJTdHJpY3QtVHJhbnNwb3J0LVNlY3VyaXR5XCIsIGhlYWRlclZhbHVlKVxuXHRcdG5leHQoKVxuXHR9XG59XG5cbmZ1bmN0aW9uIHhDb250ZW50VHlwZU9wdGlvbnMoKSB7XG5cdHJldHVybiBmdW5jdGlvbiB4Q29udGVudFR5cGVPcHRpb25zTWlkZGxld2FyZShfcmVxLCByZXMsIG5leHQpIHtcblx0XHRyZXMuc2V0SGVhZGVyKFwiWC1Db250ZW50LVR5cGUtT3B0aW9uc1wiLCBcIm5vc25pZmZcIilcblx0XHRuZXh0KClcblx0fVxufVxuXG5mdW5jdGlvbiB4RG5zUHJlZmV0Y2hDb250cm9sKG9wdGlvbnMgPSB7fSkge1xuXHRjb25zdCBoZWFkZXJWYWx1ZSA9IG9wdGlvbnMuYWxsb3cgPyBcIm9uXCIgOiBcIm9mZlwiXG5cdHJldHVybiBmdW5jdGlvbiB4RG5zUHJlZmV0Y2hDb250cm9sTWlkZGxld2FyZShfcmVxLCByZXMsIG5leHQpIHtcblx0XHRyZXMuc2V0SGVhZGVyKFwiWC1ETlMtUHJlZmV0Y2gtQ29udHJvbFwiLCBoZWFkZXJWYWx1ZSlcblx0XHRuZXh0KClcblx0fVxufVxuXG5mdW5jdGlvbiB4RG93bmxvYWRPcHRpb25zKCkge1xuXHRyZXR1cm4gZnVuY3Rpb24geERvd25sb2FkT3B0aW9uc01pZGRsZXdhcmUoX3JlcSwgcmVzLCBuZXh0KSB7XG5cdFx0cmVzLnNldEhlYWRlcihcIlgtRG93bmxvYWQtT3B0aW9uc1wiLCBcIm5vb3BlblwiKVxuXHRcdG5leHQoKVxuXHR9XG59XG5cbmZ1bmN0aW9uIGdldEhlYWRlclZhbHVlRnJvbU9wdGlvbnMkMSh7YWN0aW9uID0gXCJzYW1lb3JpZ2luXCJ9KSB7XG5cdGNvbnN0IG5vcm1hbGl6ZWRBY3Rpb24gPSB0eXBlb2YgYWN0aW9uID09PSBcInN0cmluZ1wiID8gYWN0aW9uLnRvVXBwZXJDYXNlKCkgOiBhY3Rpb25cblx0c3dpdGNoIChub3JtYWxpemVkQWN0aW9uKSB7XG5cdFx0Y2FzZSBcIlNBTUUtT1JJR0lOXCI6XG5cdFx0XHRyZXR1cm4gXCJTQU1FT1JJR0lOXCJcblx0XHRjYXNlIFwiREVOWVwiOlxuXHRcdGNhc2UgXCJTQU1FT1JJR0lOXCI6XG5cdFx0XHRyZXR1cm4gbm9ybWFsaXplZEFjdGlvblxuXHRcdGRlZmF1bHQ6XG5cdFx0XHR0aHJvdyBuZXcgRXJyb3IoYFgtRnJhbWUtT3B0aW9ucyByZWNlaXZlZCBhbiBpbnZhbGlkIGFjdGlvbiAke0pTT04uc3RyaW5naWZ5KGFjdGlvbil9YClcblx0fVxufVxuZnVuY3Rpb24geEZyYW1lT3B0aW9ucyhvcHRpb25zID0ge30pIHtcblx0Y29uc3QgaGVhZGVyVmFsdWUgPSBnZXRIZWFkZXJWYWx1ZUZyb21PcHRpb25zJDEob3B0aW9ucylcblx0cmV0dXJuIGZ1bmN0aW9uIHhGcmFtZU9wdGlvbnNNaWRkbGV3YXJlKF9yZXEsIHJlcywgbmV4dCkge1xuXHRcdHJlcy5zZXRIZWFkZXIoXCJYLUZyYW1lLU9wdGlvbnNcIiwgaGVhZGVyVmFsdWUpXG5cdFx0bmV4dCgpXG5cdH1cbn1cblxuY29uc3QgQUxMT1dFRF9QRVJNSVRURURfUE9MSUNJRVMgPSBuZXcgU2V0KFtcIm5vbmVcIiwgXCJtYXN0ZXItb25seVwiLCBcImJ5LWNvbnRlbnQtdHlwZVwiLCBcImFsbFwiXSlcbmZ1bmN0aW9uIGdldEhlYWRlclZhbHVlRnJvbU9wdGlvbnMoe3Blcm1pdHRlZFBvbGljaWVzID0gXCJub25lXCJ9KSB7XG5cdGlmIChBTExPV0VEX1BFUk1JVFRFRF9QT0xJQ0lFUy5oYXMocGVybWl0dGVkUG9saWNpZXMpKSB7XG5cdFx0cmV0dXJuIHBlcm1pdHRlZFBvbGljaWVzXG5cdH0gZWxzZSB7XG5cdFx0dGhyb3cgbmV3IEVycm9yKGBYLVBlcm1pdHRlZC1Dcm9zcy1Eb21haW4tUG9saWNpZXMgZG9lcyBub3Qgc3VwcG9ydCAke0pTT04uc3RyaW5naWZ5KHBlcm1pdHRlZFBvbGljaWVzKX1gKVxuXHR9XG59XG5mdW5jdGlvbiB4UGVybWl0dGVkQ3Jvc3NEb21haW5Qb2xpY2llcyhvcHRpb25zID0ge30pIHtcblx0Y29uc3QgaGVhZGVyVmFsdWUgPSBnZXRIZWFkZXJWYWx1ZUZyb21PcHRpb25zKG9wdGlvbnMpXG5cdHJldHVybiBmdW5jdGlvbiB4UGVybWl0dGVkQ3Jvc3NEb21haW5Qb2xpY2llc01pZGRsZXdhcmUoX3JlcSwgcmVzLCBuZXh0KSB7XG5cdFx0cmVzLnNldEhlYWRlcihcIlgtUGVybWl0dGVkLUNyb3NzLURvbWFpbi1Qb2xpY2llc1wiLCBoZWFkZXJWYWx1ZSlcblx0XHRuZXh0KClcblx0fVxufVxuXG5mdW5jdGlvbiB4UG93ZXJlZEJ5KCkge1xuXHRyZXR1cm4gZnVuY3Rpb24geFBvd2VyZWRCeU1pZGRsZXdhcmUoX3JlcSwgcmVzLCBuZXh0KSB7XG5cdFx0cmVzLnJlbW92ZUhlYWRlcihcIlgtUG93ZXJlZC1CeVwiKVxuXHRcdG5leHQoKVxuXHR9XG59XG5cbmZ1bmN0aW9uIHhYc3NQcm90ZWN0aW9uKCkge1xuXHRyZXR1cm4gZnVuY3Rpb24geFhzc1Byb3RlY3Rpb25NaWRkbGV3YXJlKF9yZXEsIHJlcywgbmV4dCkge1xuXHRcdHJlcy5zZXRIZWFkZXIoXCJYLVhTUy1Qcm90ZWN0aW9uXCIsIFwiMFwiKVxuXHRcdG5leHQoKVxuXHR9XG59XG5cbmZ1bmN0aW9uIGdldEFyZ3Mob3B0aW9uLCBtaWRkbGV3YXJlQ29uZmlnID0ge30pIHtcblx0c3dpdGNoIChvcHRpb24pIHtcblx0XHRjYXNlIHVuZGVmaW5lZDpcblx0XHRjYXNlIHRydWU6XG5cdFx0XHRyZXR1cm4gW11cblx0XHRjYXNlIGZhbHNlOlxuXHRcdFx0cmV0dXJuIG51bGxcblx0XHRkZWZhdWx0OlxuXHRcdFx0aWYgKG1pZGRsZXdhcmVDb25maWcudGFrZXNPcHRpb25zID09PSBmYWxzZSkge1xuXHRcdFx0XHRjb25zb2xlLndhcm4oYCR7bWlkZGxld2FyZUNvbmZpZy5uYW1lfSBkb2VzIG5vdCB0YWtlIG9wdGlvbnMuIFJlbW92ZSB0aGUgcHJvcGVydHkgdG8gc2lsZW5jZSB0aGlzIHdhcm5pbmcuYClcblx0XHRcdFx0cmV0dXJuIFtdXG5cdFx0XHR9IGVsc2Uge1xuXHRcdFx0XHRyZXR1cm4gW29wdGlvbl1cblx0XHRcdH1cblx0fVxufVxuZnVuY3Rpb24gZ2V0TWlkZGxld2FyZUZ1bmN0aW9uc0Zyb21PcHRpb25zKG9wdGlvbnMpIHtcblx0Y29uc3QgcmVzdWx0ID0gW11cblx0Y29uc3QgY29udGVudFNlY3VyaXR5UG9saWN5QXJncyA9IGdldEFyZ3Mob3B0aW9ucy5jb250ZW50U2VjdXJpdHlQb2xpY3kpXG5cdGlmIChjb250ZW50U2VjdXJpdHlQb2xpY3lBcmdzKSB7XG5cdFx0cmVzdWx0LnB1c2goY29udGVudFNlY3VyaXR5UG9saWN5KC4uLmNvbnRlbnRTZWN1cml0eVBvbGljeUFyZ3MpKVxuXHR9XG5cdGNvbnN0IGNyb3NzT3JpZ2luRW1iZWRkZXJQb2xpY3lBcmdzID0gZ2V0QXJncyhvcHRpb25zLmNyb3NzT3JpZ2luRW1iZWRkZXJQb2xpY3kpXG5cdGlmIChjcm9zc09yaWdpbkVtYmVkZGVyUG9saWN5QXJncykge1xuXHRcdHJlc3VsdC5wdXNoKGNyb3NzT3JpZ2luRW1iZWRkZXJQb2xpY3koLi4uY3Jvc3NPcmlnaW5FbWJlZGRlclBvbGljeUFyZ3MpKVxuXHR9XG5cdGNvbnN0IGNyb3NzT3JpZ2luT3BlbmVyUG9saWN5QXJncyA9IGdldEFyZ3Mob3B0aW9ucy5jcm9zc09yaWdpbk9wZW5lclBvbGljeSlcblx0aWYgKGNyb3NzT3JpZ2luT3BlbmVyUG9saWN5QXJncykge1xuXHRcdHJlc3VsdC5wdXNoKGNyb3NzT3JpZ2luT3BlbmVyUG9saWN5KC4uLmNyb3NzT3JpZ2luT3BlbmVyUG9saWN5QXJncykpXG5cdH1cblx0Y29uc3QgY3Jvc3NPcmlnaW5SZXNvdXJjZVBvbGljeUFyZ3MgPSBnZXRBcmdzKG9wdGlvbnMuY3Jvc3NPcmlnaW5SZXNvdXJjZVBvbGljeSlcblx0aWYgKGNyb3NzT3JpZ2luUmVzb3VyY2VQb2xpY3lBcmdzKSB7XG5cdFx0cmVzdWx0LnB1c2goY3Jvc3NPcmlnaW5SZXNvdXJjZVBvbGljeSguLi5jcm9zc09yaWdpblJlc291cmNlUG9saWN5QXJncykpXG5cdH1cblx0Y29uc3QgeERuc1ByZWZldGNoQ29udHJvbEFyZ3MgPSBnZXRBcmdzKG9wdGlvbnMuZG5zUHJlZmV0Y2hDb250cm9sKVxuXHRpZiAoeERuc1ByZWZldGNoQ29udHJvbEFyZ3MpIHtcblx0XHRyZXN1bHQucHVzaCh4RG5zUHJlZmV0Y2hDb250cm9sKC4uLnhEbnNQcmVmZXRjaENvbnRyb2xBcmdzKSlcblx0fVxuXHRjb25zdCBleHBlY3RDdEFyZ3MgPSBvcHRpb25zLmV4cGVjdEN0ICYmIGdldEFyZ3Mob3B0aW9ucy5leHBlY3RDdClcblx0aWYgKGV4cGVjdEN0QXJncykge1xuXHRcdHJlc3VsdC5wdXNoKGV4cGVjdEN0KC4uLmV4cGVjdEN0QXJncykpXG5cdH1cblx0Y29uc3QgeEZyYW1lT3B0aW9uc0FyZ3MgPSBnZXRBcmdzKG9wdGlvbnMuZnJhbWVndWFyZClcblx0aWYgKHhGcmFtZU9wdGlvbnNBcmdzKSB7XG5cdFx0cmVzdWx0LnB1c2goeEZyYW1lT3B0aW9ucyguLi54RnJhbWVPcHRpb25zQXJncykpXG5cdH1cblx0Y29uc3QgeFBvd2VyZWRCeUFyZ3MgPSBnZXRBcmdzKG9wdGlvbnMuaGlkZVBvd2VyZWRCeSwge1xuXHRcdG5hbWU6IFwiaGlkZVBvd2VyZWRCeVwiLFxuXHRcdHRha2VzT3B0aW9uczogZmFsc2Vcblx0fSlcblx0aWYgKHhQb3dlcmVkQnlBcmdzKSB7XG5cdFx0cmVzdWx0LnB1c2goeFBvd2VyZWRCeSgpKVxuXHR9XG5cdGNvbnN0IHN0cmljdFRyYW5zcG9ydFNlY3VyaXR5QXJncyA9IGdldEFyZ3Mob3B0aW9ucy5oc3RzKVxuXHRpZiAoc3RyaWN0VHJhbnNwb3J0U2VjdXJpdHlBcmdzKSB7XG5cdFx0cmVzdWx0LnB1c2goc3RyaWN0VHJhbnNwb3J0U2VjdXJpdHkoLi4uc3RyaWN0VHJhbnNwb3J0U2VjdXJpdHlBcmdzKSlcblx0fVxuXHRjb25zdCB4RG93bmxvYWRPcHRpb25zQXJncyA9IGdldEFyZ3Mob3B0aW9ucy5pZU5vT3Blbiwge1xuXHRcdG5hbWU6IFwiaWVOb09wZW5cIixcblx0XHR0YWtlc09wdGlvbnM6IGZhbHNlXG5cdH0pXG5cdGlmICh4RG93bmxvYWRPcHRpb25zQXJncykge1xuXHRcdHJlc3VsdC5wdXNoKHhEb3dubG9hZE9wdGlvbnMoKSlcblx0fVxuXHRjb25zdCB4Q29udGVudFR5cGVPcHRpb25zQXJncyA9IGdldEFyZ3Mob3B0aW9ucy5ub1NuaWZmLCB7XG5cdFx0bmFtZTogXCJub1NuaWZmXCIsXG5cdFx0dGFrZXNPcHRpb25zOiBmYWxzZVxuXHR9KVxuXHRpZiAoeENvbnRlbnRUeXBlT3B0aW9uc0FyZ3MpIHtcblx0XHRyZXN1bHQucHVzaCh4Q29udGVudFR5cGVPcHRpb25zKCkpXG5cdH1cblx0Y29uc3Qgb3JpZ2luQWdlbnRDbHVzdGVyQXJncyA9IGdldEFyZ3Mob3B0aW9ucy5vcmlnaW5BZ2VudENsdXN0ZXIsIHtcblx0XHRuYW1lOiBcIm9yaWdpbkFnZW50Q2x1c3RlclwiLFxuXHRcdHRha2VzT3B0aW9uczogZmFsc2Vcblx0fSlcblx0aWYgKG9yaWdpbkFnZW50Q2x1c3RlckFyZ3MpIHtcblx0XHRyZXN1bHQucHVzaChvcmlnaW5BZ2VudENsdXN0ZXIoKSlcblx0fVxuXHRjb25zdCB4UGVybWl0dGVkQ3Jvc3NEb21haW5Qb2xpY2llc0FyZ3MgPSBnZXRBcmdzKG9wdGlvbnMucGVybWl0dGVkQ3Jvc3NEb21haW5Qb2xpY2llcylcblx0aWYgKHhQZXJtaXR0ZWRDcm9zc0RvbWFpblBvbGljaWVzQXJncykge1xuXHRcdHJlc3VsdC5wdXNoKHhQZXJtaXR0ZWRDcm9zc0RvbWFpblBvbGljaWVzKC4uLnhQZXJtaXR0ZWRDcm9zc0RvbWFpblBvbGljaWVzQXJncykpXG5cdH1cblx0Y29uc3QgcmVmZXJyZXJQb2xpY3lBcmdzID0gZ2V0QXJncyhvcHRpb25zLnJlZmVycmVyUG9saWN5KVxuXHRpZiAocmVmZXJyZXJQb2xpY3lBcmdzKSB7XG5cdFx0cmVzdWx0LnB1c2gocmVmZXJyZXJQb2xpY3koLi4ucmVmZXJyZXJQb2xpY3lBcmdzKSlcblx0fVxuXHRjb25zdCB4WHNzUHJvdGVjdGlvbkFyZ3MgPSBnZXRBcmdzKG9wdGlvbnMueHNzRmlsdGVyLCB7XG5cdFx0bmFtZTogXCJ4c3NGaWx0ZXJcIixcblx0XHR0YWtlc09wdGlvbnM6IGZhbHNlXG5cdH0pXG5cdGlmICh4WHNzUHJvdGVjdGlvbkFyZ3MpIHtcblx0XHRyZXN1bHQucHVzaCh4WHNzUHJvdGVjdGlvbigpKVxuXHR9XG5cdHJldHVybiByZXN1bHRcbn1cbmNvbnN0IGhlbG1ldCA9IE9iamVjdC5hc3NpZ24oXG5cdGZ1bmN0aW9uIGhlbG1ldChvcHRpb25zID0ge30pIHtcblx0XHR2YXIgX2Fcblx0XHQvLyBQZW9wbGUgc2hvdWxkIGJlIGFibGUgdG8gcGFzcyBhbiBvcHRpb25zIG9iamVjdCB3aXRoIG5vIHByb3RvdHlwZSxcblx0XHQvLyBzbyB3ZSB3YW50IHRoaXMgb3B0aW9uYWwgY2hhaW5pbmcuXG5cdFx0Ly8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIEB0eXBlc2NyaXB0LWVzbGludC9uby11bm5lY2Vzc2FyeS1jb25kaXRpb25cblx0XHRpZiAoKChfYSA9IG9wdGlvbnMuY29uc3RydWN0b3IpID09PSBudWxsIHx8IF9hID09PSB2b2lkIDAgPyB2b2lkIDAgOiBfYS5uYW1lKSA9PT0gXCJJbmNvbWluZ01lc3NhZ2VcIikge1xuXHRcdFx0dGhyb3cgbmV3IEVycm9yKFwiSXQgYXBwZWFycyB5b3UgaGF2ZSBkb25lIHNvbWV0aGluZyBsaWtlIGBhcHAudXNlKGhlbG1ldClgLCBidXQgaXQgc2hvdWxkIGJlIGBhcHAudXNlKGhlbG1ldCgpKWAuXCIpXG5cdFx0fVxuXHRcdGNvbnN0IG1pZGRsZXdhcmVGdW5jdGlvbnMgPSBnZXRNaWRkbGV3YXJlRnVuY3Rpb25zRnJvbU9wdGlvbnMob3B0aW9ucylcblx0XHRyZXR1cm4gZnVuY3Rpb24gaGVsbWV0TWlkZGxld2FyZShyZXEsIHJlcywgbmV4dCkge1xuXHRcdFx0bGV0IG1pZGRsZXdhcmVJbmRleCA9IDBcblx0XHRcdDsoZnVuY3Rpb24gaW50ZXJuYWxOZXh0KGVycikge1xuXHRcdFx0XHRpZiAoZXJyKSB7XG5cdFx0XHRcdFx0bmV4dChlcnIpXG5cdFx0XHRcdFx0cmV0dXJuXG5cdFx0XHRcdH1cblx0XHRcdFx0Y29uc3QgbWlkZGxld2FyZUZ1bmN0aW9uID0gbWlkZGxld2FyZUZ1bmN0aW9uc1ttaWRkbGV3YXJlSW5kZXhdXG5cdFx0XHRcdGlmIChtaWRkbGV3YXJlRnVuY3Rpb24pIHtcblx0XHRcdFx0XHRtaWRkbGV3YXJlSW5kZXgrK1xuXHRcdFx0XHRcdG1pZGRsZXdhcmVGdW5jdGlvbihyZXEsIHJlcywgaW50ZXJuYWxOZXh0KVxuXHRcdFx0XHR9IGVsc2Uge1xuXHRcdFx0XHRcdG5leHQoKVxuXHRcdFx0XHR9XG5cdFx0XHR9KSgpXG5cdFx0fVxuXHR9LFxuXHR7XG5cdFx0Y29udGVudFNlY3VyaXR5UG9saWN5LFxuXHRcdGNyb3NzT3JpZ2luRW1iZWRkZXJQb2xpY3ksXG5cdFx0Y3Jvc3NPcmlnaW5PcGVuZXJQb2xpY3ksXG5cdFx0Y3Jvc3NPcmlnaW5SZXNvdXJjZVBvbGljeSxcblx0XHRkbnNQcmVmZXRjaENvbnRyb2w6IHhEbnNQcmVmZXRjaENvbnRyb2wsXG5cdFx0ZXhwZWN0Q3QsXG5cdFx0ZnJhbWVndWFyZDogeEZyYW1lT3B0aW9ucyxcblx0XHRoaWRlUG93ZXJlZEJ5OiB4UG93ZXJlZEJ5LFxuXHRcdGhzdHM6IHN0cmljdFRyYW5zcG9ydFNlY3VyaXR5LFxuXHRcdGllTm9PcGVuOiB4RG93bmxvYWRPcHRpb25zLFxuXHRcdG5vU25pZmY6IHhDb250ZW50VHlwZU9wdGlvbnMsXG5cdFx0b3JpZ2luQWdlbnRDbHVzdGVyLFxuXHRcdHBlcm1pdHRlZENyb3NzRG9tYWluUG9saWNpZXM6IHhQZXJtaXR0ZWRDcm9zc0RvbWFpblBvbGljaWVzLFxuXHRcdHJlZmVycmVyUG9saWN5LFxuXHRcdHhzc0ZpbHRlcjogeFhzc1Byb3RlY3Rpb25cblx0fVxuKVxuXG5leHBvcnQge2NvbnRlbnRTZWN1cml0eVBvbGljeSwgY3Jvc3NPcmlnaW5FbWJlZGRlclBvbGljeSwgY3Jvc3NPcmlnaW5PcGVuZXJQb2xpY3ksIGNyb3NzT3JpZ2luUmVzb3VyY2VQb2xpY3ksIGhlbG1ldCBhcyBkZWZhdWx0LCB4RG5zUHJlZmV0Y2hDb250cm9sIGFzIGRuc1ByZWZldGNoQ29udHJvbCwgZXhwZWN0Q3QsIHhGcmFtZU9wdGlvbnMgYXMgZnJhbWVndWFyZCwgeFBvd2VyZWRCeSBhcyBoaWRlUG93ZXJlZEJ5LCBzdHJpY3RUcmFuc3BvcnRTZWN1cml0eSBhcyBoc3RzLCB4RG93bmxvYWRPcHRpb25zIGFzIGllTm9PcGVuLCB4Q29udGVudFR5cGVPcHRpb25zIGFzIG5vU25pZmYsIG9yaWdpbkFnZW50Q2x1c3RlciwgeFBlcm1pdHRlZENyb3NzRG9tYWluUG9saWNpZXMgYXMgcGVybWl0dGVkQ3Jvc3NEb21haW5Qb2xpY2llcywgcmVmZXJyZXJQb2xpY3ksIHhYc3NQcm90ZWN0aW9uIGFzIHhzc0ZpbHRlcn1cbiIsIi8vIGdsb2JhbFxuZXhwb3J0IGNvbnN0IElOVEVSTkFMX1NFUlZFUiA9ICfQktC40L3QuNC60LvQsCDQv9C+0LzQuNC70LrQsCc7XG5leHBvcnQgY29uc3QgSU5WQUxJRF9EQVRBID0gJ9Cd0LXQutC+0YDQtdC60YLQvdGWINC00LDQvdGWJztcbi8vIGRhdGFcbmV4cG9ydCBjb25zdCBOT1RfRk9VTkQgPSAn0J7QsWDRlNC60YIg0L3QtSDQt9C90LDQudC00LXQvdC+Jztcbi8vIGxvZ2luXG5leHBvcnQgY29uc3QgTE9HSU4gPSAn0J3QtdC/0YDQsNCy0LjQu9GM0L3QuNC5INC70L7Qs9GW0L0g0LDQsdC+INC/0LDRgNC+0LvRjCc7XG4iLCIvLyAyMDBcbmV4cG9ydCBjb25zdCBPSyA9IDIwMDtcbmV4cG9ydCBjb25zdCBDUkVBVEVEID0gMjAxO1xuZXhwb3J0IGNvbnN0IEFDQ0VQVEVEID0gMjAyO1xuZXhwb3J0IGNvbnN0IE5PX0NPTlRFTlQgPSAyMDQ7XG4vLyA0MDBcbmV4cG9ydCBjb25zdCBCQURfUkVRVUVTVCA9IDQwMDtcbmV4cG9ydCBjb25zdCBVTkFVVEhPUklaRUQgPSA0MDE7XG5leHBvcnQgY29uc3QgRk9SQklEREVOID0gNDAzO1xuZXhwb3J0IGNvbnN0IE5PVF9GT1VORCA9IDQwNDtcbmV4cG9ydCBjb25zdCBNRVRIT0RfTk9UX0FMTE9XRUQgPSA0MDU7XG5leHBvcnQgY29uc3QgTk9UX0FDQ0VQVEFCTEUgPSA0MDY7XG5leHBvcnQgY29uc3QgUkVRVUVTVF9USU1FT1VUID0gNDA4O1xuZXhwb3J0IGNvbnN0IENPTkZMSUNUID0gNDA5O1xuZXhwb3J0IGNvbnN0IFBBWUxPQURfVE9PX0xBUkdFID0gNDEzO1xuZXhwb3J0IGNvbnN0IFVSSV9UT09fTE9ORyA9IDQxNDtcbmV4cG9ydCBjb25zdCBVTlNVUFBPUlRFRF9NRURJQV9UWVBFID0gNDE1O1xuZXhwb3J0IGNvbnN0IFJBTkdFX05PVF9TQVRJU0ZJQUJMRSA9IDQxNjtcbmV4cG9ydCBjb25zdCBUT09fTUFOWV9SRVFVRVNUUyA9IDQyOTtcbmV4cG9ydCBjb25zdCBSRVFVRVNUX0hFQURFUl9GSUVMRFNfVE9PX0xBUkdFID0gNDMxO1xuZXhwb3J0IGNvbnN0IFVOQVZBSUxBQkxFX0ZPUl9MRUdBTF9SRUFTT05TID0gNDUxO1xuLy8gNTAwXG5leHBvcnQgY29uc3QgSU5URVJOQUxfU0VSVkVSX0VSUk9SID0gNTAwO1xuZXhwb3J0IGNvbnN0IE5PVF9JTVBMRU1FTlRFRCA9IDUwMTtcbmV4cG9ydCBjb25zdCBCQURfR0FURVdBWSA9IDUwMjtcbmV4cG9ydCBjb25zdCBTRVJWSUNFX1VOQVZBSUxBQkxFID0gNTAzO1xuZXhwb3J0IGNvbnN0IEdBVEVXQVlfVElNRU9VVCA9IDUwNDtcbmV4cG9ydCBjb25zdCBMT09QX0RFVEVDVEVEID0gNTA4O1xuZXhwb3J0IGNvbnN0IE5FVFdPUktfQVVUSEVOVElDQVRJT05fUkVRVUlSRUQgPSA1MTE7XG4iLCJpbXBvcnQgKiBhcyBFUlJPUiBmcm9tICcuL2Vycm9yTWVzc2FnZXMnO1xuaW1wb3J0ICogYXMgU1RBVFVTIGZyb20gJy4vc3RhdHVzQ29kZXMnO1xuZXhwb3J0IGNsYXNzIEFwaUVycm9yIHtcbiAgICBzdGF0dXM7XG4gICAgbWVzc2FnZTtcbiAgICBlcnJvcjtcbiAgICBjb25zdHJ1Y3RvcihwYXJhbXMpIHtcbiAgICAgICAgY29uc3QgeyBzdGF0dXMsIG1lc3NhZ2UsIGVycm9yIH0gPSBwYXJhbXM7XG4gICAgICAgIHRoaXMuc3RhdHVzID0gc3RhdHVzO1xuICAgICAgICB0aGlzLm1lc3NhZ2UgPSBtZXNzYWdlO1xuICAgICAgICB0aGlzLmVycm9yID0gZXJyb3IgPz8gJyc7XG4gICAgfVxuICAgIHN0YXRpYyBpbnRlcm5hbFNlcnZlckVycm9yKGVycm9yKSB7XG4gICAgICAgIGNvbnNvbGUuZXJyb3IoZXJyb3IpO1xuICAgICAgICByZXR1cm4gbmV3IEFwaUVycm9yKHtcbiAgICAgICAgICAgIHN0YXR1czogU1RBVFVTLklOVEVSTkFMX1NFUlZFUl9FUlJPUixcbiAgICAgICAgICAgIG1lc3NhZ2U6IEVSUk9SLklOVEVSTkFMX1NFUlZFUixcbiAgICAgICAgICAgIGVycm9yLFxuICAgICAgICB9KTtcbiAgICB9XG4gICAgLy8gVE9ETyBpbXBsZW1lbnRcbiAgICBub3RpZnkoKSB7IH1cbn1cbiIsImV4cG9ydCBjbGFzcyBBcGlTdWNjZXNzIHtcbiAgICBzdGF0dXM7XG4gICAgbWVzc2FnZTtcbiAgICBkYXRhO1xuICAgIGNvbnN0cnVjdG9yKHBhcmFtcykge1xuICAgICAgICBjb25zdCB7IHN0YXR1cywgbWVzc2FnZSwgZGF0YSB9ID0gcGFyYW1zO1xuICAgICAgICB0aGlzLnN0YXR1cyA9IHN0YXR1cztcbiAgICAgICAgdGhpcy5tZXNzYWdlID0gbWVzc2FnZTtcbiAgICAgICAgdGhpcy5kYXRhID0gZGF0YTtcbiAgICB9XG59XG4iLCJpbXBvcnQgeyBTY2hlbWEsIG1vZGVsLCBtb2RlbHMgfSBmcm9tICdtb25nb29zZSc7XG5jb25zdCBMYWJTY2hlbWEgPSBuZXcgU2NoZW1hKHtcbiAgICBuYW1lOiB7XG4gICAgICAgIHR5cGU6IFN0cmluZyxcbiAgICAgICAgcmVxdWlyZWQ6IHRydWUsXG4gICAgfSxcbiAgICByYXRpbmc6IHtcbiAgICAgICAgdHlwZTogTnVtYmVyLFxuICAgICAgICByZXF1aXJlZDogdHJ1ZSxcbiAgICB9LFxuICAgIG1lc3NhZ2U6IHtcbiAgICAgICAgdHlwZTogU3RyaW5nLFxuICAgICAgICByZXF1aXJlZDogdHJ1ZSxcbiAgICB9LFxufSk7XG5leHBvcnQgY29uc3QgRGlzY2lwbGluZVNjaGVtYSA9IG5ldyBTY2hlbWEoe1xuICAgIG5hbWU6IHtcbiAgICAgICAgdHlwZTogU3RyaW5nLFxuICAgICAgICByZXF1aXJlZDogdHJ1ZSxcbiAgICB9LFxuICAgIHRlYWNoZXI6IHtcbiAgICAgICAgdHlwZTogU3RyaW5nLFxuICAgICAgICByZXF1aXJlZDogdHJ1ZSxcbiAgICB9LFxuICAgIHRlYWNoZXJFbWFpbDoge1xuICAgICAgICB0eXBlOiBTdHJpbmcsXG4gICAgICAgIHJlcXVpcmVkOiB0cnVlLFxuICAgIH0sXG4gICAgbGFiczoge1xuICAgICAgICB0eXBlOiBbTGFiU2NoZW1hXSxcbiAgICAgICAgcmVxdWlyZWQ6IHRydWUsXG4gICAgfSxcbn0pO1xuY29uc3QgU3BlY2lhbGl0aWVTY2hlbWEgPSBuZXcgU2NoZW1hKHtcbiAgICBpZDoge1xuICAgICAgICB0eXBlOiBTdHJpbmcsXG4gICAgICAgIHJlcXVpcmVkOiB0cnVlLFxuICAgIH0sXG4gICAgbmFtZToge1xuICAgICAgICB0eXBlOiBTdHJpbmcsXG4gICAgICAgIHJlcXVpcmVkOiB0cnVlLFxuICAgIH0sXG4gICAgZGlzY2lwbGluZXM6IHtcbiAgICAgICAgdHlwZTogW0Rpc2NpcGxpbmVTY2hlbWFdLFxuICAgICAgICByZXF1aXJlZDogdHJ1ZSxcbiAgICB9LFxufSk7XG5jb25zdCBVbml2ZXJzaXR5U2NoZW1hID0gbmV3IFNjaGVtYSh7XG4gICAgX2lkOiB7XG4gICAgICAgIHR5cGU6IE51bWJlcixcbiAgICAgICAgcmVxdWlyZWQ6IHRydWUsXG4gICAgfSxcbiAgICBpZDoge1xuICAgICAgICB0eXBlOiBTdHJpbmcsXG4gICAgICAgIHJlcXVpcmVkOiB0cnVlLFxuICAgIH0sXG4gICAgbmFtZToge1xuICAgICAgICB0eXBlOiBTdHJpbmcsXG4gICAgICAgIHJlcXVpcmVkOiB0cnVlLFxuICAgIH0sXG4gICAgYWJicjoge1xuICAgICAgICB0eXBlOiBTdHJpbmcsXG4gICAgICAgIHJlcXVpcmVkOiB0cnVlLFxuICAgIH0sXG4gICAgc3BlY2lhbGl0aWVzOiB7XG4gICAgICAgIHR5cGU6IFtTcGVjaWFsaXRpZVNjaGVtYV0sXG4gICAgICAgIHJlcXVpcmVkOiB0cnVlLFxuICAgIH0sXG59KTtcbmV4cG9ydCBjb25zdCBVbml2ZXJzaXR5TW9kZWwgPSBtb2RlbHMuVW5pdmVyc2l0eSA/PyBtb2RlbCgnVW5pdmVyc2l0eScsIFVuaXZlcnNpdHlTY2hlbWEpO1xuIiwiaW1wb3J0IHsgU2NoZW1hLCBtb2RlbCwgbW9kZWxzIH0gZnJvbSAnbW9uZ29vc2UnO1xuaW1wb3J0IHsgRGlzY2lwbGluZVNjaGVtYSB9IGZyb20gJy4vVW5pdmVyc2l0eSc7XG5jb25zdCBVc2VyU2NoZW1hID0gbmV3IFNjaGVtYSh7XG4gICAgZW1haWw6IHtcbiAgICAgICAgdHlwZTogU3RyaW5nLFxuICAgICAgICByZXF1aXJlZDogZmFsc2UsXG4gICAgICAgIGRlZmF1bHQ6ICcnLFxuICAgIH0sXG4gICAgcGFzc3dvcmQ6IHtcbiAgICAgICAgdHlwZTogU3RyaW5nLFxuICAgICAgICByZXF1aXJlZDogZmFsc2UsXG4gICAgICAgIGRlZmF1bHQ6ICcnLFxuICAgIH0sXG4gICAgbmFtZToge1xuICAgICAgICB0eXBlOiBTdHJpbmcsXG4gICAgICAgIHJlcXVpcmVkOiBmYWxzZSxcbiAgICAgICAgZGVmYXVsdDogJycsXG4gICAgfSxcbiAgICBwZXJtczoge1xuICAgICAgICB0eXBlOiBTdHJpbmcsXG4gICAgICAgIHJlcXVpcmVkOiB0cnVlLFxuICAgIH0sXG4gICAgdW5pdmVyc2l0eV9pZDoge1xuICAgICAgICB0eXBlOiBTdHJpbmcsXG4gICAgICAgIHJlcXVpcmVkOiBmYWxzZSxcbiAgICAgICAgZGVmYXVsdDogJycsXG4gICAgfSxcbiAgICBzcGVjaWFsaXR5X2lkOiB7XG4gICAgICAgIHR5cGU6IFN0cmluZyxcbiAgICAgICAgcmVxdWlyZWQ6IGZhbHNlLFxuICAgICAgICBkZWZhdWx0OiAnJyxcbiAgICB9LFxuICAgIGRpc2NpcGxpbmVzOiB7XG4gICAgICAgIHR5cGU6IFtEaXNjaXBsaW5lU2NoZW1hXSxcbiAgICAgICAgcmVxdWlyZWQ6IGZhbHNlLFxuICAgICAgICBkZWZhdWx0OiBbXSxcbiAgICB9LFxufSk7XG5Vc2VyU2NoZW1hLm1ldGhvZHMuaXNQYXNzd29yZENvcnJlY3QgPSBhc3luYyBmdW5jdGlvbiAocGFzc3dvcmQpIHtcbiAgICByZXR1cm4gdGhpcy5wYXNzd29yZCA9PT0gcGFzc3dvcmQ7XG59O1xuZXhwb3J0IGNvbnN0IFVzZXJNb2RlbCA9IG1vZGVscy5Vc2VyID8/IG1vZGVsKCdVc2VyJywgVXNlclNjaGVtYSk7XG4iLCJpbXBvcnQgeyBBcGlFcnJvciwgQXBpU3VjY2VzcywgU1RBVFVTIH0gZnJvbSAnQC9hcGkvcmVzcG9uc2VzJztcbmltcG9ydCB7IFVzZXJNb2RlbCB9IGZyb20gJ0AvRGF0YWJhc2UvbW9kZWxzL1VzZXInO1xuZXhwb3J0IGNvbnN0IHBvc3QgPSBhc3luYyAocmVxLCByZXMpID0+IHtcbiAgICB0cnkge1xuICAgICAgICBjb25zdCB7IGVtYWlsLCBwYXNzd29yZCB9ID0gcmVxLmJvZHk7XG4gICAgICAgIGlmIChlbWFpbCA9PT0gdW5kZWZpbmVkIHx8IHBhc3N3b3JkID09PSB1bmRlZmluZWQpIHtcbiAgICAgICAgICAgIGNvbnN0IHJlc3BvbnNlID0gbmV3IEFwaUVycm9yKHtcbiAgICAgICAgICAgICAgICBzdGF0dXM6IFNUQVRVUy5CQURfUkVRVUVTVCxcbiAgICAgICAgICAgICAgICBtZXNzYWdlOiAnTWlzc2luZyByZXF1aXJlZCBmaWVsZHMnLFxuICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICByZXR1cm4gcmVzLnN0YXR1cyhyZXNwb25zZS5zdGF0dXMpLnNlbmQocmVzcG9uc2UpO1xuICAgICAgICB9XG4gICAgICAgIGNvbnN0IHVzZXIgPSBhd2FpdCBVc2VyTW9kZWwuZmluZE9uZSh7IGVtYWlsIH0pO1xuICAgICAgICBjb25zdCBpc1Bhc3N3b3JkQ29ycmVjdCA9IGF3YWl0ICgoKSA9PiB7XG4gICAgICAgICAgICBpZiAodXNlciA9PT0gbnVsbClcbiAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICByZXR1cm4gdXNlci5pc1Bhc3N3b3JkQ29ycmVjdChwYXNzd29yZCk7XG4gICAgICAgIH0pKCk7XG4gICAgICAgIGlmICghaXNQYXNzd29yZENvcnJlY3QpIHtcbiAgICAgICAgICAgIGNvbnN0IHJlc3BvbnNlID0gbmV3IEFwaUVycm9yKHtcbiAgICAgICAgICAgICAgICBzdGF0dXM6IFNUQVRVUy5VTkFVVEhPUklaRUQsXG4gICAgICAgICAgICAgICAgbWVzc2FnZTogJ0VtYWlsIG9yIHBhc3N3b3JkIGlzIGluY29ycmVjdCcsXG4gICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIHJldHVybiByZXMuc3RhdHVzKHJlc3BvbnNlLnN0YXR1cykuc2VuZChyZXNwb25zZSk7XG4gICAgICAgIH1cbiAgICAgICAgY29uc3QgcmVzcG9uc2UgPSBuZXcgQXBpU3VjY2Vzcyh7XG4gICAgICAgICAgICBzdGF0dXM6IFNUQVRVUy5PSyxcbiAgICAgICAgICAgIG1lc3NhZ2U6ICdTdWNjZXNzJyxcbiAgICAgICAgICAgIGRhdGE6IHVzZXIsXG4gICAgICAgIH0pO1xuICAgICAgICByZXR1cm4gcmVzLnN0YXR1cyhyZXNwb25zZS5zdGF0dXMpLnNlbmQocmVzcG9uc2UpO1xuICAgIH1cbiAgICBjYXRjaCAoZXJyb3IpIHtcbiAgICAgICAgY29uc3QgcmVzcG9uc2UgPSBBcGlFcnJvci5pbnRlcm5hbFNlcnZlckVycm9yKGVycm9yKTtcbiAgICAgICAgcmV0dXJuIHJlcy5zdGF0dXMocmVzcG9uc2Uuc3RhdHVzKS5zZW5kKHJlc3BvbnNlKTtcbiAgICB9XG4gICAgZmluYWxseSB7XG4gICAgICAgIHJlcy5lbmQoKTtcbiAgICB9XG59O1xuIiwiaW1wb3J0IHsgUm91dGVyIH0gZnJvbSAnZXhwcmVzcyc7XG5pbXBvcnQgeyBwb3N0IH0gZnJvbSAnQC9hcGkvY29udHJvbGxlcnMvbG9naW4nO1xuY29uc3QgbG9naW5Sb3V0ZXIgPSBSb3V0ZXIoKTtcbmxvZ2luUm91dGVyLnBvc3QoJy8nLCBwb3N0KTtcbmV4cG9ydCB7IGxvZ2luUm91dGVyIH07XG4iLCJpbXBvcnQgeyBBcGlFcnJvciwgQXBpU3VjY2VzcywgU1RBVFVTIH0gZnJvbSAnQC9hcGkvcmVzcG9uc2VzJztcbmltcG9ydCB7IFVuaXZlcnNpdHlNb2RlbCB9IGZyb20gJ0AvRGF0YWJhc2UvbW9kZWxzJztcbmV4cG9ydCBjb25zdCBnZXQgPSBhc3luYyAocmVxLCByZXMpID0+IHtcbiAgICB0cnkge1xuICAgICAgICBjb25zdCB7IGlkLCBhYmJyIH0gPSByZXEuYm9keTtcbiAgICAgICAgY29uc3QgZGF0YSA9IGF3YWl0IChhc3luYyAoKSA9PiB7XG4gICAgICAgICAgICBpZiAoaWQgIT09IHVuZGVmaW5lZCkge1xuICAgICAgICAgICAgICAgIHJldHVybiBhd2FpdCBVbml2ZXJzaXR5TW9kZWwuZmluZCh7IGlkIH0pLmxlYW4oKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGlmIChhYmJyICE9PSB1bmRlZmluZWQpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gYXdhaXQgVW5pdmVyc2l0eU1vZGVsLmZpbmQoeyBhYmJyIH0pLmxlYW4oKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHJldHVybiBhd2FpdCBVbml2ZXJzaXR5TW9kZWwuZmluZCgpLmxlYW4oKTtcbiAgICAgICAgfSkoKTtcbiAgICAgICAgY29uc3QgcmVzcG9uc2UgPSBuZXcgQXBpU3VjY2Vzcyh7XG4gICAgICAgICAgICBzdGF0dXM6IFNUQVRVUy5PSyxcbiAgICAgICAgICAgIG1lc3NhZ2U6ICdTdWNjZXNzJyxcbiAgICAgICAgICAgIGRhdGEsXG4gICAgICAgIH0pO1xuICAgICAgICByZXR1cm4gcmVzLnN0YXR1cyhyZXNwb25zZS5zdGF0dXMpLnNlbmQocmVzcG9uc2UpO1xuICAgIH1cbiAgICBjYXRjaCAoZXJyb3IpIHtcbiAgICAgICAgY29uc3QgcmVzcG9uc2UgPSBBcGlFcnJvci5pbnRlcm5hbFNlcnZlckVycm9yKGVycm9yKTtcbiAgICAgICAgcmV0dXJuIHJlcy5zdGF0dXMocmVzcG9uc2Uuc3RhdHVzKS5zZW5kKHJlc3BvbnNlKTtcbiAgICB9XG4gICAgZmluYWxseSB7XG4gICAgICAgIHJlcy5lbmQoKTtcbiAgICB9XG59O1xuIiwiaW1wb3J0IHsgUm91dGVyIH0gZnJvbSAnZXhwcmVzcyc7XG5pbXBvcnQgeyBnZXQgfSBmcm9tICdAL2FwaS9jb250cm9sbGVycy91bml2ZXJzaXR5JztcbmNvbnN0IHVuaXZlcnNpdHlSb3V0ZXIgPSBSb3V0ZXIoKTtcbnVuaXZlcnNpdHlSb3V0ZXIuZ2V0KCcvJywgZ2V0KTtcbmV4cG9ydCB7IHVuaXZlcnNpdHlSb3V0ZXIgfTtcbiIsImltcG9ydCB7IEFwaUVycm9yLCBBcGlTdWNjZXNzLCBTVEFUVVMgfSBmcm9tICdAL2FwaS9yZXNwb25zZXMnO1xuaW1wb3J0IHsgVXNlck1vZGVsIH0gZnJvbSAnQC9EYXRhYmFzZS9tb2RlbHMvVXNlcic7XG5leHBvcnQgY29uc3QgZ2V0ID0gYXN5bmMgKHJlcSwgcmVzKSA9PiB7XG4gICAgdHJ5IHtcbiAgICAgICAgY29uc3QgeyB0ZWFjaGVyRW1haWwgfSA9IHJlcS5ib2R5O1xuICAgICAgICBpZiAodGVhY2hlckVtYWlsID09PSB1bmRlZmluZWQpIHtcbiAgICAgICAgICAgIGNvbnN0IHJlc3BvbnNlID0gbmV3IEFwaUVycm9yKHtcbiAgICAgICAgICAgICAgICBzdGF0dXM6IFNUQVRVUy5CQURfUkVRVUVTVCxcbiAgICAgICAgICAgICAgICBtZXNzYWdlOiAnTWlzc2luZyByZXF1aXJlZCBmaWVsZHMnLFxuICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICByZXR1cm4gcmVzLnN0YXR1cyhyZXNwb25zZS5zdGF0dXMpLnNlbmQocmVzcG9uc2UpO1xuICAgICAgICB9XG4gICAgICAgIGNvbnN0IHN0dWRlbnRzID0gYXdhaXQgVXNlck1vZGVsLmZpbmQoe1xuICAgICAgICAgICAgZGlzY2lwbGluZXM6IHsgJGVsZW1NYXRjaDogeyB0ZWFjaGVyRW1haWwgfSB9LFxuICAgICAgICB9KS5sZWFuKCk7XG4gICAgICAgIGNvbnN0IHJlc3BvbnNlID0gbmV3IEFwaVN1Y2Nlc3Moe1xuICAgICAgICAgICAgc3RhdHVzOiBTVEFUVVMuT0ssXG4gICAgICAgICAgICBtZXNzYWdlOiAnU3VjY2VzcycsXG4gICAgICAgICAgICBkYXRhOiBzdHVkZW50cyxcbiAgICAgICAgfSk7XG4gICAgICAgIHJldHVybiByZXMuc3RhdHVzKHJlc3BvbnNlLnN0YXR1cykuc2VuZChyZXNwb25zZSk7XG4gICAgfVxuICAgIGNhdGNoIChlcnJvcikge1xuICAgICAgICBjb25zdCByZXNwb25zZSA9IEFwaUVycm9yLmludGVybmFsU2VydmVyRXJyb3IoZXJyb3IpO1xuICAgICAgICByZXR1cm4gcmVzLnN0YXR1cyhyZXNwb25zZS5zdGF0dXMpLnNlbmQocmVzcG9uc2UpO1xuICAgIH1cbiAgICBmaW5hbGx5IHtcbiAgICAgICAgcmVzLmVuZCgpO1xuICAgIH1cbn07XG4iLCJpbXBvcnQgeyBBcGlFcnJvciwgQXBpU3VjY2VzcywgU1RBVFVTIH0gZnJvbSAnQC9hcGkvcmVzcG9uc2VzJztcbmltcG9ydCB7IFVzZXJNb2RlbCB9IGZyb20gJ0AvRGF0YWJhc2UvbW9kZWxzL1VzZXInO1xuZXhwb3J0IGNvbnN0IHB1dCA9IGFzeW5jIChyZXEsIHJlcykgPT4ge1xuICAgIHRyeSB7XG4gICAgICAgIGNvbnN0IHsgc3R1ZGVudEVtYWlsLCB0ZWFjaGVyRW1haWwsIGxhYk5hbWUsIHJhdGluZywgbWVzc2FnZSwgcG9pbnRzIH0gPSByZXEuYm9keTtcbiAgICAgICAgaWYgKHN0dWRlbnRFbWFpbCA9PT0gdW5kZWZpbmVkIHx8XG4gICAgICAgICAgICB0ZWFjaGVyRW1haWwgPT09IHVuZGVmaW5lZCB8fFxuICAgICAgICAgICAgbGFiTmFtZSA9PT0gdW5kZWZpbmVkIHx8XG4gICAgICAgICAgICByYXRpbmcgPT09IHVuZGVmaW5lZCB8fFxuICAgICAgICAgICAgbWVzc2FnZSA9PT0gdW5kZWZpbmVkIHx8XG4gICAgICAgICAgICBwb2ludHMgPT09IHVuZGVmaW5lZCkge1xuICAgICAgICAgICAgY29uc3QgcmVzcG9uc2UgPSBuZXcgQXBpRXJyb3Ioe1xuICAgICAgICAgICAgICAgIHN0YXR1czogU1RBVFVTLkJBRF9SRVFVRVNULFxuICAgICAgICAgICAgICAgIG1lc3NhZ2U6ICdNaXNzaW5nIHJlcXVpcmVkIGZpZWxkcycsXG4gICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIHJldHVybiByZXMuc3RhdHVzKHJlc3BvbnNlLnN0YXR1cykuc2VuZChyZXNwb25zZSk7XG4gICAgICAgIH1cbiAgICAgICAgY29uc3QgdXBkYXRlZFN0dWRlbnQgPSBhd2FpdCBVc2VyTW9kZWwuZmluZE9uZUFuZFVwZGF0ZSh7XG4gICAgICAgICAgICBlbWFpbDogc3R1ZGVudEVtYWlsLFxuICAgICAgICAgICAgJ2Rpc2NpcGxpbmVzLnRlYWNoZXJFbWFpbCc6IHRlYWNoZXJFbWFpbCxcbiAgICAgICAgICAgICdkaXNjaXBsaW5lcy5sYWJzLm5hbWUnOiBsYWJOYW1lLFxuICAgICAgICB9LCB7XG4gICAgICAgICAgICAkc2V0OiB7XG4gICAgICAgICAgICAgICAgJ2Rpc2NpcGxpbmVzLiRbZGlzY2lwbGluZV0ubGFicy4kW2xhYl0ucmF0aW5nJzogcmF0aW5nLFxuICAgICAgICAgICAgICAgICdkaXNjaXBsaW5lcy4kW2Rpc2NpcGxpbmVdLmxhYnMuJFtsYWJdLm1lc3NhZ2UnOiBtZXNzYWdlLFxuICAgICAgICAgICAgICAgICdkaXNjaXBsaW5lcy4kW2Rpc2NpcGxpbmVdLmxhYnMuJFtsYWJdLnBvaW50cyc6IHBvaW50cyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgIH0sIHtcbiAgICAgICAgICAgIGFycmF5RmlsdGVyczogW1xuICAgICAgICAgICAgICAgIHsgJ2Rpc2NpcGxpbmUudGVhY2hlckVtYWlsJzogdGVhY2hlckVtYWlsIH0sXG4gICAgICAgICAgICAgICAgeyAnbGFiLm5hbWUnOiBsYWJOYW1lIH0sXG4gICAgICAgICAgICBdLFxuICAgICAgICAgICAgbmV3OiB0cnVlLFxuICAgICAgICB9KTtcbiAgICAgICAgY29uc3QgcmVzcG9uc2UgPSBuZXcgQXBpU3VjY2Vzcyh7XG4gICAgICAgICAgICBzdGF0dXM6IFNUQVRVUy5PSyxcbiAgICAgICAgICAgIG1lc3NhZ2U6ICdTdWNjZXNzJyxcbiAgICAgICAgICAgIGRhdGE6IHVwZGF0ZWRTdHVkZW50LFxuICAgICAgICB9KTtcbiAgICAgICAgcmV0dXJuIHJlcy5zdGF0dXMocmVzcG9uc2Uuc3RhdHVzKS5zZW5kKHJlc3BvbnNlKTtcbiAgICB9XG4gICAgY2F0Y2ggKGVycm9yKSB7XG4gICAgICAgIGNvbnN0IHJlc3BvbnNlID0gQXBpRXJyb3IuaW50ZXJuYWxTZXJ2ZXJFcnJvcihlcnJvcik7XG4gICAgICAgIHJldHVybiByZXMuc3RhdHVzKHJlc3BvbnNlLnN0YXR1cykuc2VuZChyZXNwb25zZSk7XG4gICAgfVxuICAgIGZpbmFsbHkge1xuICAgICAgICByZXMuZW5kKCk7XG4gICAgfVxufTtcbiIsImltcG9ydCB7IFJvdXRlciB9IGZyb20gJ2V4cHJlc3MnO1xuaW1wb3J0IHsgZ2V0LCBwdXQgfSBmcm9tICdAL2FwaS9jb250cm9sbGVycy9zdHVkZW50JztcbmNvbnN0IHN0dWRlbnRSb3V0ZXIgPSBSb3V0ZXIoKTtcbnN0dWRlbnRSb3V0ZXIuZ2V0KCcvJywgZ2V0KTtcbnN0dWRlbnRSb3V0ZXIucHV0KCcvJywgcHV0KTtcbmV4cG9ydCB7IHN0dWRlbnRSb3V0ZXIgfTtcbiIsImltcG9ydCB7IEFwaUVycm9yLCBBcGlTdWNjZXNzLCBTVEFUVVMgfSBmcm9tICdAL2FwaS9yZXNwb25zZXMnO1xuaW1wb3J0IHsgVXNlck1vZGVsIH0gZnJvbSAnQC9EYXRhYmFzZS9tb2RlbHMvVXNlcic7XG5leHBvcnQgY29uc3QgZGVsID0gYXN5bmMgKHJlcSwgcmVzKSA9PiB7XG4gICAgdHJ5IHtcbiAgICAgICAgY29uc3QgeyBlbWFpbCB9ID0gcmVxLmJvZHk7XG4gICAgICAgIGlmIChlbWFpbCA9PT0gdW5kZWZpbmVkKSB7XG4gICAgICAgICAgICBjb25zdCByZXNwb25zZSA9IG5ldyBBcGlFcnJvcih7XG4gICAgICAgICAgICAgICAgc3RhdHVzOiBTVEFUVVMuQkFEX1JFUVVFU1QsXG4gICAgICAgICAgICAgICAgbWVzc2FnZTogJ01pc3NpbmcgcmVxdWlyZWQgZmllbGRzJyxcbiAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgcmV0dXJuIHJlcy5zdGF0dXMocmVzcG9uc2Uuc3RhdHVzKS5zZW5kKHJlc3BvbnNlKTtcbiAgICAgICAgfVxuICAgICAgICBjb25zdCBmb3VuZCA9IFVzZXJNb2RlbC5maW5kT25lKHsgZW1haWwgfSk7XG4gICAgICAgIGlmIChmb3VuZCA9PT0gbnVsbCB8fCBmb3VuZCA9PT0gdW5kZWZpbmVkKSB7XG4gICAgICAgICAgICBjb25zdCByZXNwb25zZSA9IG5ldyBBcGlFcnJvcih7XG4gICAgICAgICAgICAgICAgc3RhdHVzOiBTVEFUVVMuQkFEX1JFUVVFU1QsXG4gICAgICAgICAgICAgICAgbWVzc2FnZTogJ1VzZXIgbm90IGZvdW5kJyxcbiAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgcmV0dXJuIHJlcy5zdGF0dXMocmVzcG9uc2Uuc3RhdHVzKS5zZW5kKHJlc3BvbnNlKTtcbiAgICAgICAgfVxuICAgICAgICBhd2FpdCBVc2VyTW9kZWwuZGVsZXRlT25lKHsgZW1haWwgfSk7XG4gICAgICAgIGNvbnN0IHJlc3BvbnNlID0gbmV3IEFwaVN1Y2Nlc3Moe1xuICAgICAgICAgICAgc3RhdHVzOiBTVEFUVVMuT0ssXG4gICAgICAgICAgICBtZXNzYWdlOiAnVXNlciBkZWxldGVkJyxcbiAgICAgICAgfSk7XG4gICAgICAgIHJldHVybiByZXMuc3RhdHVzKHJlc3BvbnNlLnN0YXR1cykuc2VuZChyZXNwb25zZSk7XG4gICAgfVxuICAgIGNhdGNoIChlcnJvcikge1xuICAgICAgICBjb25zdCByZXNwb25zZSA9IEFwaUVycm9yLmludGVybmFsU2VydmVyRXJyb3IoZXJyb3IpO1xuICAgICAgICByZXR1cm4gcmVzLnN0YXR1cyhyZXNwb25zZS5zdGF0dXMpLnNlbmQocmVzcG9uc2UpO1xuICAgIH1cbiAgICBmaW5hbGx5IHtcbiAgICAgICAgcmVzLmVuZCgpO1xuICAgIH1cbn07XG4iLCJpbXBvcnQgeyBBcGlFcnJvciwgU1RBVFVTIH0gZnJvbSAnQC9hcGkvcmVzcG9uc2VzJztcbmltcG9ydCB7IFVzZXJNb2RlbCB9IGZyb20gJ0AvRGF0YWJhc2UvbW9kZWxzL1VzZXInO1xuZXhwb3J0IGNvbnN0IHBvc3QgPSBhc3luYyAocmVxLCByZXMpID0+IHtcbiAgICB0cnkge1xuICAgICAgICBjb25zdCB7IGVtYWlsLCBwYXNzd29yZCwgbmFtZSwgdW5pdmVyc2l0eUlkLCBzcGVjaWFsaXR5SWQsIHBlcm1zIH0gPSByZXEuYm9keTtcbiAgICAgICAgaWYgKGVtYWlsID09PSB1bmRlZmluZWQgfHxcbiAgICAgICAgICAgIHBhc3N3b3JkID09PSB1bmRlZmluZWQgfHxcbiAgICAgICAgICAgIG5hbWUgPT09IHVuZGVmaW5lZCB8fFxuICAgICAgICAgICAgdW5pdmVyc2l0eUlkID09PSB1bmRlZmluZWQgfHxcbiAgICAgICAgICAgIHNwZWNpYWxpdHlJZCA9PT0gdW5kZWZpbmVkIHx8XG4gICAgICAgICAgICBwZXJtcyA9PT0gdW5kZWZpbmVkKSB7XG4gICAgICAgICAgICBjb25zdCByZXNwb25zZSA9IG5ldyBBcGlFcnJvcih7XG4gICAgICAgICAgICAgICAgc3RhdHVzOiBTVEFUVVMuQkFEX1JFUVVFU1QsXG4gICAgICAgICAgICAgICAgbWVzc2FnZTogJ01pc3NpbmcgcmVxdWlyZWQgZmllbGRzJyxcbiAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgcmV0dXJuIHJlcy5zdGF0dXMocmVzcG9uc2Uuc3RhdHVzKS5zZW5kKHJlc3BvbnNlKTtcbiAgICAgICAgfVxuICAgICAgICBjb25zdCB1c2VyRXhpc3RzID0gYXdhaXQgVXNlck1vZGVsLmV4aXN0cyh7IGVtYWlsIH0pO1xuICAgICAgICBpZiAodXNlckV4aXN0cykge1xuICAgICAgICAgICAgY29uc3QgcmVzcG9uc2UgPSBuZXcgQXBpRXJyb3Ioe1xuICAgICAgICAgICAgICAgIHN0YXR1czogU1RBVFVTLkJBRF9SRVFVRVNULFxuICAgICAgICAgICAgICAgIG1lc3NhZ2U6ICdFbWFpbCBhbHJlYWR5IGluIHVzZScsXG4gICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIHJldHVybiByZXMuc3RhdHVzKHJlc3BvbnNlLnN0YXR1cykuc2VuZChyZXNwb25zZSk7XG4gICAgICAgIH1cbiAgICAgICAgY29uc3QgdXNlciA9IGF3YWl0IFVzZXJNb2RlbC5jcmVhdGUoe1xuICAgICAgICAgICAgZW1haWwsXG4gICAgICAgICAgICBwYXNzd29yZCxcbiAgICAgICAgICAgIG5hbWUsXG4gICAgICAgICAgICBwZXJtcyxcbiAgICAgICAgICAgIHVuaXZlcnNpdHlfaWQ6IHVuaXZlcnNpdHlJZCxcbiAgICAgICAgICAgIHNwZWNpYWxpdHlfaWQ6IHNwZWNpYWxpdHlJZCxcbiAgICAgICAgfSk7XG4gICAgICAgIGNvbnN0IHZhbGlkYXRpb25FcnJvciA9IHVzZXIudmFsaWRhdGVTeW5jKCk7XG4gICAgICAgIGlmICh2YWxpZGF0aW9uRXJyb3IgIT09IHVuZGVmaW5lZCkge1xuICAgICAgICAgICAgY29uc3QgcmVzcG9uc2UgPSBuZXcgQXBpRXJyb3Ioe1xuICAgICAgICAgICAgICAgIHN0YXR1czogU1RBVFVTLkJBRF9SRVFVRVNULFxuICAgICAgICAgICAgICAgIG1lc3NhZ2U6ICdWYWxpZGF0aW9uIGVycm9yJyxcbiAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgcmV0dXJuIHJlcy5zdGF0dXMocmVzcG9uc2Uuc3RhdHVzKS5zZW5kKHJlc3BvbnNlKTtcbiAgICAgICAgfVxuICAgICAgICBhd2FpdCB1c2VyLnNhdmUoKTtcbiAgICAgICAgY29uc3QgcmVzcG9uc2UgPSB7XG4gICAgICAgICAgICBzdGF0dXM6IFNUQVRVUy5PSyxcbiAgICAgICAgICAgIG1lc3NhZ2U6ICdVc2VyIGNyZWF0ZWQnLFxuICAgICAgICAgICAgZGF0YTogdXNlcixcbiAgICAgICAgfTtcbiAgICAgICAgcmV0dXJuIHJlcy5zdGF0dXMocmVzcG9uc2Uuc3RhdHVzKS5zZW5kKHJlc3BvbnNlKTtcbiAgICB9XG4gICAgY2F0Y2ggKGVycm9yKSB7XG4gICAgICAgIGNvbnN0IHJlc3BvbnNlID0gQXBpRXJyb3IuaW50ZXJuYWxTZXJ2ZXJFcnJvcihlcnJvcik7XG4gICAgICAgIHJldHVybiByZXMuc3RhdHVzKHJlc3BvbnNlLnN0YXR1cykuc2VuZChyZXNwb25zZSk7XG4gICAgfVxuICAgIGZpbmFsbHkge1xuICAgICAgICByZXMuZW5kKCk7XG4gICAgfVxufTtcbiIsImltcG9ydCB7IFJvdXRlciB9IGZyb20gJ2V4cHJlc3MnO1xuaW1wb3J0IHsgZGVsLCBwb3N0IH0gZnJvbSAnQC9hcGkvY29udHJvbGxlcnMvYWRtaW4nO1xuY29uc3QgYWRtaW5Sb3V0ZXIgPSBSb3V0ZXIoKTtcbmFkbWluUm91dGVyLnBvc3QoJy91c2VyJywgcG9zdCk7XG5hZG1pblJvdXRlci5kZWxldGUoJy91c2VyJywgZGVsKTtcbmV4cG9ydCB7IGFkbWluUm91dGVyIH07XG4iLCJpbXBvcnQgeyBSb3V0ZXIgfSBmcm9tICdleHByZXNzJztcbmltcG9ydCB7IGxvZ2luUm91dGVyLCB1bml2ZXJzaXR5Um91dGVyIH0gZnJvbSAnLi9yb3V0ZXMnO1xuaW1wb3J0IHsgc3R1ZGVudFJvdXRlciB9IGZyb20gJ0AvYXBpL3JvdXRlcy9zdHVkZW50Um91dGVyJztcbmltcG9ydCB7IGFkbWluUm91dGVyIH0gZnJvbSAnLi9yb3V0ZXMvYWRtaW5Sb3V0ZXInO1xuY29uc3QgYXBpUm91dGVyID0gUm91dGVyKCk7XG5hcGlSb3V0ZXIudXNlKCcvdW5pdmVyc2l0eScsIHVuaXZlcnNpdHlSb3V0ZXIpO1xuYXBpUm91dGVyLnVzZSgnL2xvZ2luJywgbG9naW5Sb3V0ZXIpO1xuYXBpUm91dGVyLnVzZSgnL3N0dWRlbnQnLCBzdHVkZW50Um91dGVyKTtcbmFwaVJvdXRlci51c2UoJy9hZG1pbicsIGFkbWluUm91dGVyKTtcbmV4cG9ydCB7IGFwaVJvdXRlciB9O1xuIiwiaW1wb3J0IGJvZHlQYXJzZXIgZnJvbSAnYm9keS1wYXJzZXInO1xuaW1wb3J0IGNvbXByZXNzaW9uIGZyb20gJ2NvbXByZXNzaW9uJztcbmltcG9ydCBjb3JzIGZyb20gJ2NvcnMnO1xuaW1wb3J0IGV4cHJlc3MgZnJvbSAnZXhwcmVzcyc7XG5pbXBvcnQgaGVsbWV0IGZyb20gJ2hlbG1ldCc7XG5pbXBvcnQgeyBhcGlSb3V0ZXIgfSBmcm9tICdAL2FwaSc7XG5jb25zdCBzZXJ2ZXIgPSBleHByZXNzKCk7XG50cnkge1xuICAgIHNlcnZlci51c2UoYm9keVBhcnNlci51cmxlbmNvZGVkKHsgZXh0ZW5kZWQ6IHRydWUgfSkpO1xuICAgIHNlcnZlci51c2UoYm9keVBhcnNlci5qc29uKCkpO1xuICAgIHNlcnZlci51c2UoY29tcHJlc3Npb24oKSk7XG4gICAgc2VydmVyLnVzZShjb3JzKCkpO1xuICAgIHNlcnZlci51c2UoaGVsbWV0KHtcbiAgICAgICAgY29udGVudFNlY3VyaXR5UG9saWN5OiBmYWxzZSxcbiAgICB9KSk7XG4gICAgc2VydmVyLnVzZSgnL2FwaScsIGFwaVJvdXRlcik7XG4gICAgY29uc29sZS5sb2coJ1tTRVJWRVJdIEluaXRpYWxpemVkJyk7XG59XG5jYXRjaCAoZXJyb3IpIHtcbiAgICBjb25zb2xlLmVycm9yKGVycm9yKTtcbn1cbmV4cG9ydCB7IHNlcnZlciB9O1xuIiwiaW1wb3J0IHsgY29uZmlnIH0gZnJvbSAnZG90ZW52JztcbmNvbmZpZygpO1xuLy8gZ2xvYmFsXG5leHBvcnQgY29uc3QgUE9SVCA9IHByb2Nlc3MuZW52LlBPUlQgPz8gNDAwMDtcbi8vIGRhdGFiYXNlXG4vLyBkYXRhYmFzZVxuZXhwb3J0IGNvbnN0IERCX1VTRVIgPSBwcm9jZXNzLmVudi5EQl9VU0VSO1xuZXhwb3J0IGNvbnN0IERCX1BBU1MgPSBwcm9jZXNzLmVudi5EQl9QQVNTO1xuZXhwb3J0IGNvbnN0IERCX05BTUUgPSBwcm9jZXNzLmVudi5EQl9OQU1FO1xuZXhwb3J0IGNvbnN0IERCX0NPTk5TVFIgPSBwcm9jZXNzLmVudi5EQl9DT05OU1RSXG4gICAgLnJlcGxhY2UoJzx1c2VyPicsIERCX1VTRVIpXG4gICAgLnJlcGxhY2UoJzxwYXNzPicsIERCX1BBU1MpXG4gICAgLnJlcGxhY2UoJzxkYj4nLCBEQl9OQU1FKTtcbiIsImltcG9ydCB7IGNvbm5lY3QsIGNvbm5lY3Rpb24sIHNldCB9IGZyb20gJ21vbmdvb3NlJztcbmltcG9ydCB7IERCX0NPTk5TVFIsIERCX05BTUUgfSBmcm9tICdAL2NvbmZpZyc7XG5zZXQoJ3N0cmljdFF1ZXJ5JywgZmFsc2UpO1xuY2xhc3MgRGF0YWJhc2Uge1xuICAgIHN0YXRpYyBpbnN0YW5jZSA9IG51bGw7XG4gICAgY29uc3RydWN0b3IoKSB7XG4gICAgICAgIGlmIChEYXRhYmFzZS5pbnN0YW5jZSA9PT0gbnVsbClcbiAgICAgICAgICAgIERhdGFiYXNlLmluc3RhbmNlID0gdGhpcztcbiAgICAgICAgcmV0dXJuIERhdGFiYXNlLmluc3RhbmNlO1xuICAgIH1cbiAgICBpc0Nvbm5lY3RlZCA9ICgpID0+IGNvbm5lY3Rpb24ucmVhZHlTdGF0ZSA9PT0gMTtcbiAgICBjb25uZWN0ID0gYXN5bmMgKCkgPT4ge1xuICAgICAgICBjb25zdCBkZWZhdWx0UmV0dXJuID0gdGhpcy5pc0Nvbm5lY3RlZDtcbiAgICAgICAgaWYgKHRoaXMuaXNDb25uZWN0ZWQoKSlcbiAgICAgICAgICAgIHJldHVybiBkZWZhdWx0UmV0dXJuO1xuICAgICAgICBjb25zb2xlLmxvZygnW0RCXSBDb25uZWN0aW5nLi4uJyk7XG4gICAgICAgIHRyeSB7XG4gICAgICAgICAgICBhd2FpdCBjb25uZWN0KERCX0NPTk5TVFIpO1xuICAgICAgICAgICAgY29uc29sZS5sb2coYFtEQl0gQ29ubmVjdGVkIHRvIFwiJHtEQl9OQU1FfVwiYCk7XG4gICAgICAgIH1cbiAgICAgICAgY2F0Y2ggKGVycm9yKSB7XG4gICAgICAgICAgICBjb25zb2xlLmVycm9yKCdbREJdIENvbm5lY3Rpb24gZXJyb3InKTtcbiAgICAgICAgICAgIGNvbnNvbGUuZXJyb3IoZXJyb3IpO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiBkZWZhdWx0UmV0dXJuO1xuICAgIH07XG59XG5leHBvcnQgeyBEYXRhYmFzZSB9O1xuIiwiY29uc3QgbG9jYWxlID0gJ3VrLVVBJztcbmNvbnN0IHRpbWVab25lID0gJ0V1cm9wZS9LaWV2JztcbmV4cG9ydCBjb25zdCBnZXRDdXJyZW50VGltZVN0cmluZyA9ICgpID0+IG5ldyBEYXRlKCkudG9Mb2NhbGVUaW1lU3RyaW5nKGxvY2FsZSwge1xuICAgIHRpbWVab25lLFxuICAgIGhvdXI6ICcyLWRpZ2l0JyxcbiAgICBtaW51dGU6ICcyLWRpZ2l0JyxcbiAgICBzZWNvbmQ6ICcyLWRpZ2l0Jyxcbn0pO1xuZXhwb3J0IGNvbnN0IGdldEN1cnJlbnREYXRlU3RyaW5nID0gKCkgPT4gbmV3IERhdGUoKS50b0xvY2FsZURhdGVTdHJpbmcobG9jYWxlLCB7XG4gICAgdGltZVpvbmUsXG4gICAgd2Vla2RheTogJ2xvbmcnLFxuICAgIHllYXI6ICdudW1lcmljJyxcbiAgICBtb250aDogJ2xvbmcnLFxuICAgIGRheTogJ251bWVyaWMnLFxuICAgIGhvdXI6ICdudW1lcmljJyxcbiAgICBtaW51dGU6ICdudW1lcmljJyxcbn0pO1xuIiwiaW1wb3J0IHsgUE9SVCB9IGZyb20gJ0AvY29uZmlnJztcbmltcG9ydCB7IGdldEN1cnJlbnRUaW1lU3RyaW5nIH0gZnJvbSAnQC91dGlscyc7XG5leHBvcnQgY29uc3QgbWFpbkxpc3RlbiA9ICgpID0+IHtcbiAgICB0cnkge1xuICAgICAgICBjb25zb2xlLmxvZyhgW1NFUlZFUl0gfCAke2dldEN1cnJlbnRUaW1lU3RyaW5nKCl9IExpc3RlbmluZyBhdCAke1BPUlR9YCk7XG4gICAgfVxuICAgIGNhdGNoIChlcnJvcikge1xuICAgICAgICBjb25zb2xlLmVycm9yKGVycm9yKTtcbiAgICB9XG59O1xuIiwiaW1wb3J0IHsgc2VydmVyIH0gZnJvbSAnLi9zZXJ2ZXInO1xuaW1wb3J0IHsgRGF0YWJhc2UgfSBmcm9tICdAL0RhdGFiYXNlJztcbmltcG9ydCB7IG1haW5MaXN0ZW4gfSBmcm9tICdAL2FwaS9jb250cm9sbGVycy9tYWluJztcbmltcG9ydCB7IFBPUlQgfSBmcm9tICdAL2NvbmZpZyc7XG5jb25zdCBzdGFydCA9IGFzeW5jICgpID0+IHtcbiAgICBjb25zdCBkYXRhYmFzZSA9IG5ldyBEYXRhYmFzZSgpO1xuICAgIHZvaWQgc2VydmVyLmxpc3RlbihQT1JULCBtYWluTGlzdGVuKTtcbiAgICB2b2lkIGRhdGFiYXNlLmNvbm5lY3QoKTtcbn07XG52b2lkIHN0YXJ0KCk7XG4iXSwibmFtZXMiOlsiU1RBVFVTLklOVEVSTkFMX1NFUlZFUl9FUlJPUiIsIkVSUk9SLklOVEVSTkFMX1NFUlZFUiIsIlNjaGVtYSIsIm1vZGVscyIsIm1vZGVsIiwicG9zdCIsIlNUQVRVUy5CQURfUkVRVUVTVCIsIlNUQVRVUy5VTkFVVEhPUklaRUQiLCJTVEFUVVMuT0siLCJSb3V0ZXIiLCJnZXQiLCJjb25maWciLCJzZXQiLCJjb25uZWN0aW9uIiwiY29ubmVjdCJdLCJtYXBwaW5ncyI6Ijs7Ozs7Ozs7O0FBQUEsTUFBTSw0QkFBNEIsR0FBRyxNQUFNLENBQUMsOEJBQThCLEVBQUM7QUFDM0UsTUFBTSxrQkFBa0IsR0FBRztBQUMzQixDQUFDLGFBQWEsRUFBRSxDQUFDLFFBQVEsQ0FBQztBQUMxQixDQUFDLFVBQVUsRUFBRSxDQUFDLFFBQVEsQ0FBQztBQUN2QixDQUFDLFVBQVUsRUFBRSxDQUFDLFFBQVEsRUFBRSxRQUFRLEVBQUUsT0FBTyxDQUFDO0FBQzFDLENBQUMsYUFBYSxFQUFFLENBQUMsUUFBUSxDQUFDO0FBQzFCLENBQUMsaUJBQWlCLEVBQUUsQ0FBQyxRQUFRLENBQUM7QUFDOUIsQ0FBQyxTQUFTLEVBQUUsQ0FBQyxRQUFRLEVBQUUsT0FBTyxDQUFDO0FBQy9CLENBQUMsWUFBWSxFQUFFLENBQUMsUUFBUSxDQUFDO0FBQ3pCLENBQUMsWUFBWSxFQUFFLENBQUMsUUFBUSxDQUFDO0FBQ3pCLENBQUMsaUJBQWlCLEVBQUUsQ0FBQyxRQUFRLENBQUM7QUFDOUIsQ0FBQyxXQUFXLEVBQUUsQ0FBQyxRQUFRLEVBQUUsUUFBUSxFQUFFLGlCQUFpQixDQUFDO0FBQ3JELENBQUMsMkJBQTJCLEVBQUUsRUFBRTtBQUNoQyxFQUFDO0FBQ0QsTUFBTSxvQkFBb0IsR0FBRyxNQUFNLE1BQU0sQ0FBQyxNQUFNLENBQUMsRUFBRSxFQUFFLGtCQUFrQixFQUFDO0FBQ3hFLE1BQU0sT0FBTyxHQUFHLEdBQUcsSUFBSSxHQUFHLENBQUMsT0FBTyxDQUFDLFFBQVEsRUFBRSxhQUFhLElBQUksR0FBRyxHQUFHLGFBQWEsQ0FBQyxXQUFXLEVBQUUsRUFBQztBQUNoRyxNQUFNLHVCQUF1QixHQUFHLGNBQWMsSUFBSSxLQUFLLENBQUMsSUFBSSxDQUFDLGNBQWMsRUFBQztBQUM1RSxNQUFNLEdBQUcsR0FBRyxD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
