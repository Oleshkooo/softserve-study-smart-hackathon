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
        const isPasswordCorrect = await user.isPasswordCorrect(password);
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
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXguanMiLCJzb3VyY2VzIjpbIi4uL25vZGVfbW9kdWxlcy9oZWxtZXQvaW5kZXgubWpzIiwiLi4vc3JjL2FwaS9yZXNwb25zZXMvZXJyb3JNZXNzYWdlcy50cyIsIi4uL3NyYy9hcGkvcmVzcG9uc2VzL3N0YXR1c0NvZGVzLnRzIiwiLi4vc3JjL2FwaS9yZXNwb25zZXMvQXBpRXJyb3IudHMiLCIuLi9zcmMvYXBpL3Jlc3BvbnNlcy9BcGlTdWNjZXNzLnRzIiwiLi4vc3JjL0RhdGFiYXNlL21vZGVscy9Vbml2ZXJzaXR5LnRzIiwiLi4vc3JjL0RhdGFiYXNlL21vZGVscy9Vc2VyLnRzIiwiLi4vc3JjL2FwaS9jb250cm9sbGVycy9sb2dpbi9wb3N0LnRzIiwiLi4vc3JjL2FwaS9yb3V0ZXMvbG9naW5Sb3V0ZXIudHMiLCIuLi9zcmMvYXBpL2NvbnRyb2xsZXJzL3VuaXZlcnNpdHkvZ2V0LnRzIiwiLi4vc3JjL2FwaS9yb3V0ZXMvdW5pdmVyc2l0eVJvdXRlci50cyIsIi4uL3NyYy9hcGkvY29udHJvbGxlcnMvc3R1ZGVudC9nZXQudHMiLCIuLi9zcmMvYXBpL2NvbnRyb2xsZXJzL3N0dWRlbnQvcHV0LnRzIiwiLi4vc3JjL2FwaS9yb3V0ZXMvc3R1ZGVudFJvdXRlci50cyIsIi4uL3NyYy9hcGkvY29udHJvbGxlcnMvYWRtaW4vZGVsLnRzIiwiLi4vc3JjL2FwaS9jb250cm9sbGVycy9hZG1pbi9wb3N0LnRzIiwiLi4vc3JjL2FwaS9yb3V0ZXMvYWRtaW5Sb3V0ZXIudHMiLCIuLi9zcmMvYXBpL2FwaVJvdXRlci50cyIsIi4uL3NyYy9zZXJ2ZXIudHMiLCIuLi9zcmMvY29uZmlnLnRzIiwiLi4vc3JjL0RhdGFiYXNlL0RhdGFiYXNlLnRzIiwiLi4vc3JjL3V0aWxzL2RhdGUudHMiLCIuLi9zcmMvYXBpL2NvbnRyb2xsZXJzL21haW4vbWFpbkxpc3Rlbi50cyIsIi4uL3NyYy9pbmRleC50cyJdLCJzb3VyY2VzQ29udGVudCI6WyJjb25zdCBkYW5nZXJvdXNseURpc2FibGVEZWZhdWx0U3JjID0gU3ltYm9sKFwiZGFuZ2Vyb3VzbHlEaXNhYmxlRGVmYXVsdFNyY1wiKVxuY29uc3QgREVGQVVMVF9ESVJFQ1RJVkVTID0ge1xuXHRcImRlZmF1bHQtc3JjXCI6IFtcIidzZWxmJ1wiXSxcblx0XCJiYXNlLXVyaVwiOiBbXCInc2VsZidcIl0sXG5cdFwiZm9udC1zcmNcIjogW1wiJ3NlbGYnXCIsIFwiaHR0cHM6XCIsIFwiZGF0YTpcIl0sXG5cdFwiZm9ybS1hY3Rpb25cIjogW1wiJ3NlbGYnXCJdLFxuXHRcImZyYW1lLWFuY2VzdG9yc1wiOiBbXCInc2VsZidcIl0sXG5cdFwiaW1nLXNyY1wiOiBbXCInc2VsZidcIiwgXCJkYXRhOlwiXSxcblx0XCJvYmplY3Qtc3JjXCI6IFtcIidub25lJ1wiXSxcblx0XCJzY3JpcHQtc3JjXCI6IFtcIidzZWxmJ1wiXSxcblx0XCJzY3JpcHQtc3JjLWF0dHJcIjogW1wiJ25vbmUnXCJdLFxuXHRcInN0eWxlLXNyY1wiOiBbXCInc2VsZidcIiwgXCJodHRwczpcIiwgXCIndW5zYWZlLWlubGluZSdcIl0sXG5cdFwidXBncmFkZS1pbnNlY3VyZS1yZXF1ZXN0c1wiOiBbXVxufVxuY29uc3QgZ2V0RGVmYXVsdERpcmVjdGl2ZXMgPSAoKSA9PiBPYmplY3QuYXNzaWduKHt9LCBERUZBVUxUX0RJUkVDVElWRVMpXG5jb25zdCBkYXNoaWZ5ID0gc3RyID0+IHN0ci5yZXBsYWNlKC9bQS1aXS9nLCBjYXBpdGFsTGV0dGVyID0+IFwiLVwiICsgY2FwaXRhbExldHRlci50b0xvd2VyQ2FzZSgpKVxuY29uc3QgaXNEaXJlY3RpdmVWYWx1ZUludmFsaWQgPSBkaXJlY3RpdmVWYWx1ZSA9PiAvO3wsLy50ZXN0KGRpcmVjdGl2ZVZhbHVlKVxuY29uc3QgaGFzID0gKG9iaiwga2V5KSA9PiBPYmplY3QucHJvdG90eXBlLmhhc093blByb3BlcnR5LmNhbGwob2JqLCBrZXkpXG5mdW5jdGlvbiBub3JtYWxpemVEaXJlY3RpdmVzKG9wdGlvbnMpIHtcblx0Y29uc3QgZGVmYXVsdERpcmVjdGl2ZXMgPSBnZXREZWZhdWx0RGlyZWN0aXZlcygpXG5cdGNvbnN0IHt1c2VEZWZhdWx0cyA9IHRydWUsIGRpcmVjdGl2ZXM6IHJhd0RpcmVjdGl2ZXMgPSBkZWZhdWx0RGlyZWN0aXZlc30gPSBvcHRpb25zXG5cdGNvbnN0IHJlc3VsdCA9IG5ldyBNYXAoKVxuXHRjb25zdCBkaXJlY3RpdmVOYW1lc1NlZW4gPSBuZXcgU2V0KClcblx0Y29uc3QgZGlyZWN0aXZlc0V4cGxpY2l0bHlEaXNhYmxlZCA9IG5ldyBTZXQoKVxuXHRmb3IgKGNvbnN0IHJhd0RpcmVjdGl2ZU5hbWUgaW4gcmF3RGlyZWN0aXZlcykge1xuXHRcdGlmICghaGFzKHJhd0RpcmVjdGl2ZXMsIHJhd0RpcmVjdGl2ZU5hbWUpKSB7XG5cdFx0XHRjb250aW51ZVxuXHRcdH1cblx0XHRpZiAocmF3RGlyZWN0aXZlTmFtZS5sZW5ndGggPT09IDAgfHwgL1teYS16QS1aMC05LV0vLnRlc3QocmF3RGlyZWN0aXZlTmFtZSkpIHtcblx0XHRcdHRocm93IG5ldyBFcnJvcihgQ29udGVudC1TZWN1cml0eS1Qb2xpY3kgcmVjZWl2ZWQgYW4gaW52YWxpZCBkaXJlY3RpdmUgbmFtZSAke0pTT04uc3RyaW5naWZ5KHJhd0RpcmVjdGl2ZU5hbWUpfWApXG5cdFx0fVxuXHRcdGNvbnN0IGRpcmVjdGl2ZU5hbWUgPSBkYXNoaWZ5KHJhd0RpcmVjdGl2ZU5hbWUpXG5cdFx0aWYgKGRpcmVjdGl2ZU5hbWVzU2Vlbi5oYXMoZGlyZWN0aXZlTmFtZSkpIHtcblx0XHRcdHRocm93IG5ldyBFcnJvcihgQ29udGVudC1TZWN1cml0eS1Qb2xpY3kgcmVjZWl2ZWQgYSBkdXBsaWNhdGUgZGlyZWN0aXZlICR7SlNPTi5zdHJpbmdpZnkoZGlyZWN0aXZlTmFtZSl9YClcblx0XHR9XG5cdFx0ZGlyZWN0aXZlTmFtZXNTZWVuLmFkZChkaXJlY3RpdmVOYW1lKVxuXHRcdGNvbnN0IHJhd0RpcmVjdGl2ZVZhbHVlID0gcmF3RGlyZWN0aXZlc1tyYXdEaXJlY3RpdmVOYW1lXVxuXHRcdGxldCBkaXJlY3RpdmVWYWx1ZVxuXHRcdGlmIChyYXdEaXJlY3RpdmVWYWx1ZSA9PT0gbnVsbCkge1xuXHRcdFx0aWYgKGRpcmVjdGl2ZU5hbWUgPT09IFwiZGVmYXVsdC1zcmNcIikge1xuXHRcdFx0XHR0aHJvdyBuZXcgRXJyb3IoXCJDb250ZW50LVNlY3VyaXR5LVBvbGljeSBuZWVkcyBhIGRlZmF1bHQtc3JjIGJ1dCBpdCB3YXMgc2V0IHRvIGBudWxsYC4gSWYgeW91IHJlYWxseSB3YW50IHRvIGRpc2FibGUgaXQsIHNldCBpdCB0byBgY29udGVudFNlY3VyaXR5UG9saWN5LmRhbmdlcm91c2x5RGlzYWJsZURlZmF1bHRTcmNgLlwiKVxuXHRcdFx0fVxuXHRcdFx0ZGlyZWN0aXZlc0V4cGxpY2l0bHlEaXNhYmxlZC5hZGQoZGlyZWN0aXZlTmFtZSlcblx0XHRcdGNvbnRpbnVlXG5cdFx0fSBlbHNlIGlmICh0eXBlb2YgcmF3RGlyZWN0aXZlVmFsdWUgPT09IFwic3RyaW5nXCIpIHtcblx0XHRcdGRpcmVjdGl2ZVZhbHVlID0gW3Jhd0RpcmVjdGl2ZVZhbHVlXVxuXHRcdH0gZWxzZSBpZiAoIXJhd0RpcmVjdGl2ZVZhbHVlKSB7XG5cdFx0XHR0aHJvdyBuZXcgRXJyb3IoYENvbnRlbnQtU2VjdXJpdHktUG9saWN5IHJlY2VpdmVkIGFuIGludmFsaWQgZGlyZWN0aXZlIHZhbHVlIGZvciAke0pTT04uc3RyaW5naWZ5KGRpcmVjdGl2ZU5hbWUpfWApXG5cdFx0fSBlbHNlIGlmIChyYXdEaXJlY3RpdmVWYWx1ZSA9PT0gZGFuZ2Vyb3VzbHlEaXNhYmxlRGVmYXVsdFNyYykge1xuXHRcdFx0aWYgKGRpcmVjdGl2ZU5hbWUgPT09IFwiZGVmYXVsdC1zcmNcIikge1xuXHRcdFx0XHRkaXJlY3RpdmVzRXhwbGljaXRseURpc2FibGVkLmFkZChcImRlZmF1bHQtc3JjXCIpXG5cdFx0XHRcdGNvbnRpbnVlXG5cdFx0XHR9IGVsc2Uge1xuXHRcdFx0XHR0aHJvdyBuZXcgRXJyb3IoYENvbnRlbnQtU2VjdXJpdHktUG9saWN5OiB0cmllZCB0byBkaXNhYmxlICR7SlNPTi5zdHJpbmdpZnkoZGlyZWN0aXZlTmFtZSl9IGFzIGlmIGl0IHdlcmUgZGVmYXVsdC1zcmM7IHNpbXBseSBvbWl0IHRoZSBrZXlgKVxuXHRcdFx0fVxuXHRcdH0gZWxzZSB7XG5cdFx0XHRkaXJlY3RpdmVWYWx1ZSA9IHJhd0RpcmVjdGl2ZVZhbHVlXG5cdFx0fVxuXHRcdGZvciAoY29uc3QgZWxlbWVudCBvZiBkaXJlY3RpdmVWYWx1ZSkge1xuXHRcdFx0aWYgKHR5cGVvZiBlbGVtZW50ID09PSBcInN0cmluZ1wiICYmIGlzRGlyZWN0aXZlVmFsdWVJbnZhbGlkKGVsZW1lbnQpKSB7XG5cdFx0XHRcdHRocm93IG5ldyBFcnJvcihgQ29udGVudC1TZWN1cml0eS1Qb2xpY3kgcmVjZWl2ZWQgYW4gaW52YWxpZCBkaXJlY3RpdmUgdmFsdWUgZm9yICR7SlNPTi5zdHJpbmdpZnkoZGlyZWN0aXZlTmFtZSl9YClcblx0XHRcdH1cblx0XHR9XG5cdFx0cmVzdWx0LnNldChkaXJlY3RpdmVOYW1lLCBkaXJlY3RpdmVWYWx1ZSlcblx0fVxuXHRpZiAodXNlRGVmYXVsdHMpIHtcblx0XHRPYmplY3QuZW50cmllcyhkZWZhdWx0RGlyZWN0aXZlcykuZm9yRWFjaCgoW2RlZmF1bHREaXJlY3RpdmVOYW1lLCBkZWZhdWx0RGlyZWN0aXZlVmFsdWVdKSA9PiB7XG5cdFx0XHRpZiAoIXJlc3VsdC5oYXMoZGVmYXVsdERpcmVjdGl2ZU5hbWUpICYmICFkaXJlY3RpdmVzRXhwbGljaXRseURpc2FibGVkLmhhcyhkZWZhdWx0RGlyZWN0aXZlTmFtZSkpIHtcblx0XHRcdFx0cmVzdWx0LnNldChkZWZhdWx0RGlyZWN0aXZlTmFtZSwgZGVmYXVsdERpcmVjdGl2ZVZhbHVlKVxuXHRcdFx0fVxuXHRcdH0pXG5cdH1cblx0aWYgKCFyZXN1bHQuc2l6ZSkge1xuXHRcdHRocm93IG5ldyBFcnJvcihcIkNvbnRlbnQtU2VjdXJpdHktUG9saWN5IGhhcyBubyBkaXJlY3RpdmVzLiBFaXRoZXIgc2V0IHNvbWUgb3IgZGlzYWJsZSB0aGUgaGVhZGVyXCIpXG5cdH1cblx0aWYgKCFyZXN1bHQuaGFzKFwiZGVmYXVsdC1zcmNcIikgJiYgIWRpcmVjdGl2ZXNFeHBsaWNpdGx5RGlzYWJsZWQuaGFzKFwiZGVmYXVsdC1zcmNcIikpIHtcblx0XHR0aHJvdyBuZXcgRXJyb3IoXCJDb250ZW50LVNlY3VyaXR5LVBvbGljeSBuZWVkcyBhIGRlZmF1bHQtc3JjIGJ1dCBub25lIHdhcyBwcm92aWRlZC4gSWYgeW91IHJlYWxseSB3YW50IHRvIGRpc2FibGUgaXQsIHNldCBpdCB0byBgY29udGVudFNlY3VyaXR5UG9saWN5LmRhbmdlcm91c2x5RGlzYWJsZURlZmF1bHRTcmNgLlwiKVxuXHR9XG5cdHJldHVybiByZXN1bHRcbn1cbmZ1bmN0aW9uIGdldEhlYWRlclZhbHVlKHJlcSwgcmVzLCBub3JtYWxpemVkRGlyZWN0aXZlcykge1xuXHRsZXQgZXJyXG5cdGNvbnN0IHJlc3VsdCA9IFtdXG5cdG5vcm1hbGl6ZWREaXJlY3RpdmVzLmZvckVhY2goKHJhd0RpcmVjdGl2ZVZhbHVlLCBkaXJlY3RpdmVOYW1lKSA9PiB7XG5cdFx0bGV0IGRpcmVjdGl2ZVZhbHVlID0gXCJcIlxuXHRcdGZvciAoY29uc3QgZWxlbWVudCBvZiByYXdEaXJlY3RpdmVWYWx1ZSkge1xuXHRcdFx0ZGlyZWN0aXZlVmFsdWUgKz0gXCIgXCIgKyAoZWxlbWVudCBpbnN0YW5jZW9mIEZ1bmN0aW9uID8gZWxlbWVudChyZXEsIHJlcykgOiBlbGVtZW50KVxuXHRcdH1cblx0XHRpZiAoIWRpcmVjdGl2ZVZhbHVlKSB7XG5cdFx0XHRyZXN1bHQucHVzaChkaXJlY3RpdmVOYW1lKVxuXHRcdH0gZWxzZSBpZiAoaXNEaXJlY3RpdmVWYWx1ZUludmFsaWQoZGlyZWN0aXZlVmFsdWUpKSB7XG5cdFx0XHRlcnIgPSBuZXcgRXJyb3IoYENvbnRlbnQtU2VjdXJpdHktUG9saWN5IHJlY2VpdmVkIGFuIGludmFsaWQgZGlyZWN0aXZlIHZhbHVlIGZvciAke0pTT04uc3RyaW5naWZ5KGRpcmVjdGl2ZU5hbWUpfWApXG5cdFx0fSBlbHNlIHtcblx0XHRcdHJlc3VsdC5wdXNoKGAke2RpcmVjdGl2ZU5hbWV9JHtkaXJlY3RpdmVWYWx1ZX1gKVxuXHRcdH1cblx0fSlcblx0cmV0dXJuIGVyciA/IGVyciA6IHJlc3VsdC5qb2luKFwiO1wiKVxufVxuY29uc3QgY29udGVudFNlY3VyaXR5UG9saWN5ID0gZnVuY3Rpb24gY29udGVudFNlY3VyaXR5UG9saWN5KG9wdGlvbnMgPSB7fSkge1xuXHRjb25zdCBoZWFkZXJOYW1lID0gb3B0aW9ucy5yZXBvcnRPbmx5ID8gXCJDb250ZW50LVNlY3VyaXR5LVBvbGljeS1SZXBvcnQtT25seVwiIDogXCJDb250ZW50LVNlY3VyaXR5LVBvbGljeVwiXG5cdGNvbnN0IG5vcm1hbGl6ZWREaXJlY3RpdmVzID0gbm9ybWFsaXplRGlyZWN0aXZlcyhvcHRpb25zKVxuXHRyZXR1cm4gZnVuY3Rpb24gY29udGVudFNlY3VyaXR5UG9saWN5TWlkZGxld2FyZShyZXEsIHJlcywgbmV4dCkge1xuXHRcdGNvbnN0IHJlc3VsdCA9IGdldEhlYWRlclZhbHVlKHJlcSwgcmVzLCBub3JtYWxpemVkRGlyZWN0aXZlcylcblx0XHRpZiAocmVzdWx0IGluc3RhbmNlb2YgRXJyb3IpIHtcblx0XHRcdG5leHQocmVzdWx0KVxuXHRcdH0gZWxzZSB7XG5cdFx0XHRyZXMuc2V0SGVhZGVyKGhlYWRlck5hbWUsIHJlc3VsdClcblx0XHRcdG5leHQoKVxuXHRcdH1cblx0fVxufVxuY29udGVudFNlY3VyaXR5UG9saWN5LmdldERlZmF1bHREaXJlY3RpdmVzID0gZ2V0RGVmYXVsdERpcmVjdGl2ZXNcbmNvbnRlbnRTZWN1cml0eVBvbGljeS5kYW5nZXJvdXNseURpc2FibGVEZWZhdWx0U3JjID0gZGFuZ2Vyb3VzbHlEaXNhYmxlRGVmYXVsdFNyY1xuXG5jb25zdCBBTExPV0VEX1BPTElDSUVTJDIgPSBuZXcgU2V0KFtcInJlcXVpcmUtY29ycFwiLCBcImNyZWRlbnRpYWxsZXNzXCJdKVxuZnVuY3Rpb24gZ2V0SGVhZGVyVmFsdWVGcm9tT3B0aW9ucyQ3KHtwb2xpY3kgPSBcInJlcXVpcmUtY29ycFwifSkge1xuXHRpZiAoQUxMT1dFRF9QT0xJQ0lFUyQyLmhhcyhwb2xpY3kpKSB7XG5cdFx0cmV0dXJuIHBvbGljeVxuXHR9IGVsc2Uge1xuXHRcdHRocm93IG5ldyBFcnJvcihgQ3Jvc3MtT3JpZ2luLUVtYmVkZGVyLVBvbGljeSBkb2VzIG5vdCBzdXBwb3J0IHRoZSAke0pTT04uc3RyaW5naWZ5KHBvbGljeSl9IHBvbGljeWApXG5cdH1cbn1cbmZ1bmN0aW9uIGNyb3NzT3JpZ2luRW1iZWRkZXJQb2xpY3kob3B0aW9ucyA9IHt9KSB7XG5cdGNvbnN0IGhlYWRlclZhbHVlID0gZ2V0SGVhZGVyVmFsdWVGcm9tT3B0aW9ucyQ3KG9wdGlvbnMpXG5cdHJldHVybiBmdW5jdGlvbiBjcm9zc09yaWdpbkVtYmVkZGVyUG9saWN5TWlkZGxld2FyZShfcmVxLCByZXMsIG5leHQpIHtcblx0XHRyZXMuc2V0SGVhZGVyKFwiQ3Jvc3MtT3JpZ2luLUVtYmVkZGVyLVBvbGljeVwiLCBoZWFkZXJWYWx1ZSlcblx0XHRuZXh0KClcblx0fVxufVxuXG5jb25zdCBBTExPV0VEX1BPTElDSUVTJDEgPSBuZXcgU2V0KFtcInNhbWUtb3JpZ2luXCIsIFwic2FtZS1vcmlnaW4tYWxsb3ctcG9wdXBzXCIsIFwidW5zYWZlLW5vbmVcIl0pXG5mdW5jdGlvbiBnZXRIZWFkZXJWYWx1ZUZyb21PcHRpb25zJDYoe3BvbGljeSA9IFwic2FtZS1vcmlnaW5cIn0pIHtcblx0aWYgKEFMTE9XRURfUE9MSUNJRVMkMS5oYXMocG9saWN5KSkge1xuXHRcdHJldHVybiBwb2xpY3lcblx0fSBlbHNlIHtcblx0XHR0aHJvdyBuZXcgRXJyb3IoYENyb3NzLU9yaWdpbi1PcGVuZXItUG9saWN5IGRvZXMgbm90IHN1cHBvcnQgdGhlICR7SlNPTi5zdHJpbmdpZnkocG9saWN5KX0gcG9saWN5YClcblx0fVxufVxuZnVuY3Rpb24gY3Jvc3NPcmlnaW5PcGVuZXJQb2xpY3kob3B0aW9ucyA9IHt9KSB7XG5cdGNvbnN0IGhlYWRlclZhbHVlID0gZ2V0SGVhZGVyVmFsdWVGcm9tT3B0aW9ucyQ2KG9wdGlvbnMpXG5cdHJldHVybiBmdW5jdGlvbiBjcm9zc09yaWdpbk9wZW5lclBvbGljeU1pZGRsZXdhcmUoX3JlcSwgcmVzLCBuZXh0KSB7XG5cdFx0cmVzLnNldEhlYWRlcihcIkNyb3NzLU9yaWdpbi1PcGVuZXItUG9saWN5XCIsIGhlYWRlclZhbHVlKVxuXHRcdG5leHQoKVxuXHR9XG59XG5cbmNvbnN0IEFMTE9XRURfUE9MSUNJRVMgPSBuZXcgU2V0KFtcInNhbWUtb3JpZ2luXCIsIFwic2FtZS1zaXRlXCIsIFwiY3Jvc3Mtb3JpZ2luXCJdKVxuZnVuY3Rpb24gZ2V0SGVhZGVyVmFsdWVGcm9tT3B0aW9ucyQ1KHtwb2xpY3kgPSBcInNhbWUtb3JpZ2luXCJ9KSB7XG5cdGlmIChBTExPV0VEX1BPTElDSUVTLmhhcyhwb2xpY3kpKSB7XG5cdFx0cmV0dXJuIHBvbGljeVxuXHR9IGVsc2Uge1xuXHRcdHRocm93IG5ldyBFcnJvcihgQ3Jvc3MtT3JpZ2luLVJlc291cmNlLVBvbGljeSBkb2VzIG5vdCBzdXBwb3J0IHRoZSAke0pTT04uc3RyaW5naWZ5KHBvbGljeSl9IHBvbGljeWApXG5cdH1cbn1cbmZ1bmN0aW9uIGNyb3NzT3JpZ2luUmVzb3VyY2VQb2xpY3kob3B0aW9ucyA9IHt9KSB7XG5cdGNvbnN0IGhlYWRlclZhbHVlID0gZ2V0SGVhZGVyVmFsdWVGcm9tT3B0aW9ucyQ1KG9wdGlvbnMpXG5cdHJldHVybiBmdW5jdGlvbiBjcm9zc09yaWdpblJlc291cmNlUG9saWN5TWlkZGxld2FyZShfcmVxLCByZXMsIG5leHQpIHtcblx0XHRyZXMuc2V0SGVhZGVyKFwiQ3Jvc3MtT3JpZ2luLVJlc291cmNlLVBvbGljeVwiLCBoZWFkZXJWYWx1ZSlcblx0XHRuZXh0KClcblx0fVxufVxuXG5mdW5jdGlvbiBwYXJzZU1heEFnZSQxKHZhbHVlID0gMCkge1xuXHRpZiAodmFsdWUgPj0gMCAmJiBOdW1iZXIuaXNGaW5pdGUodmFsdWUpKSB7XG5cdFx0cmV0dXJuIE1hdGguZmxvb3IodmFsdWUpXG5cdH0gZWxzZSB7XG5cdFx0dGhyb3cgbmV3IEVycm9yKGBFeHBlY3QtQ1Q6ICR7SlNPTi5zdHJpbmdpZnkodmFsdWUpfSBpcyBub3QgYSB2YWxpZCB2YWx1ZSBmb3IgbWF4QWdlLiBQbGVhc2UgY2hvb3NlIGEgcG9zaXRpdmUgaW50ZWdlci5gKVxuXHR9XG59XG5mdW5jdGlvbiBnZXRIZWFkZXJWYWx1ZUZyb21PcHRpb25zJDQob3B0aW9ucykge1xuXHRjb25zdCBkaXJlY3RpdmVzID0gW2BtYXgtYWdlPSR7cGFyc2VNYXhBZ2UkMShvcHRpb25zLm1heEFnZSl9YF1cblx0aWYgKG9wdGlvbnMuZW5mb3JjZSkge1xuXHRcdGRpcmVjdGl2ZXMucHVzaChcImVuZm9yY2VcIilcblx0fVxuXHRpZiAob3B0aW9ucy5yZXBvcnRVcmkpIHtcblx0XHRkaXJlY3RpdmVzLnB1c2goYHJlcG9ydC11cmk9XCIke29wdGlvbnMucmVwb3J0VXJpfVwiYClcblx0fVxuXHRyZXR1cm4gZGlyZWN0aXZlcy5qb2luKFwiLCBcIilcbn1cbmZ1bmN0aW9uIGV4cGVjdEN0KG9wdGlvbnMgPSB7fSkge1xuXHRjb25zdCBoZWFkZXJWYWx1ZSA9IGdldEhlYWRlclZhbHVlRnJvbU9wdGlvbnMkNChvcHRpb25zKVxuXHRyZXR1cm4gZnVuY3Rpb24gZXhwZWN0Q3RNaWRkbGV3YXJlKF9yZXEsIHJlcywgbmV4dCkge1xuXHRcdHJlcy5zZXRIZWFkZXIoXCJFeHBlY3QtQ1RcIiwgaGVhZGVyVmFsdWUpXG5cdFx0bmV4dCgpXG5cdH1cbn1cblxuZnVuY3Rpb24gb3JpZ2luQWdlbnRDbHVzdGVyKCkge1xuXHRyZXR1cm4gZnVuY3Rpb24gb3JpZ2luQWdlbnRDbHVzdGVyTWlkZGxld2FyZShfcmVxLCByZXMsIG5leHQpIHtcblx0XHRyZXMuc2V0SGVhZGVyKFwiT3JpZ2luLUFnZW50LUNsdXN0ZXJcIiwgXCI/MVwiKVxuXHRcdG5leHQoKVxuXHR9XG59XG5cbmNvbnN0IEFMTE9XRURfVE9LRU5TID0gbmV3IFNldChbXCJuby1yZWZlcnJlclwiLCBcIm5vLXJlZmVycmVyLXdoZW4tZG93bmdyYWRlXCIsIFwic2FtZS1vcmlnaW5cIiwgXCJvcmlnaW5cIiwgXCJzdHJpY3Qtb3JpZ2luXCIsIFwib3JpZ2luLXdoZW4tY3Jvc3Mtb3JpZ2luXCIsIFwic3RyaWN0LW9yaWdpbi13aGVuLWNyb3NzLW9yaWdpblwiLCBcInVuc2FmZS11cmxcIiwgXCJcIl0pXG5mdW5jdGlvbiBnZXRIZWFkZXJWYWx1ZUZyb21PcHRpb25zJDMoe3BvbGljeSA9IFtcIm5vLXJlZmVycmVyXCJdfSkge1xuXHRjb25zdCB0b2tlbnMgPSB0eXBlb2YgcG9saWN5ID09PSBcInN0cmluZ1wiID8gW3BvbGljeV0gOiBwb2xpY3lcblx0aWYgKHRva2Vucy5sZW5ndGggPT09IDApIHtcblx0XHR0aHJvdyBuZXcgRXJyb3IoXCJSZWZlcnJlci1Qb2xpY3kgcmVjZWl2ZWQgbm8gcG9saWN5IHRva2Vuc1wiKVxuXHR9XG5cdGNvbnN0IHRva2Vuc1NlZW4gPSBuZXcgU2V0KClcblx0dG9rZW5zLmZvckVhY2godG9rZW4gPT4ge1xuXHRcdGlmICghQUxMT1dFRF9UT0tFTlMuaGFzKHRva2VuKSkge1xuXHRcdFx0dGhyb3cgbmV3IEVycm9yKGBSZWZlcnJlci1Qb2xpY3kgcmVjZWl2ZWQgYW4gdW5leHBlY3RlZCBwb2xpY3kgdG9rZW4gJHtKU09OLnN0cmluZ2lmeSh0b2tlbil9YClcblx0XHR9IGVsc2UgaWYgKHRva2Vuc1NlZW4uaGFzKHRva2VuKSkge1xuXHRcdFx0dGhyb3cgbmV3IEVycm9yKGBSZWZlcnJlci1Qb2xpY3kgcmVjZWl2ZWQgYSBkdXBsaWNhdGUgcG9saWN5IHRva2VuICR7SlNPTi5zdHJpbmdpZnkodG9rZW4pfWApXG5cdFx0fVxuXHRcdHRva2Vuc1NlZW4uYWRkKHRva2VuKVxuXHR9KVxuXHRyZXR1cm4gdG9rZW5zLmpvaW4oXCIsXCIpXG59XG5mdW5jdGlvbiByZWZlcnJlclBvbGljeShvcHRpb25zID0ge30pIHtcblx0Y29uc3QgaGVhZGVyVmFsdWUgPSBnZXRIZWFkZXJWYWx1ZUZyb21PcHRpb25zJDMob3B0aW9ucylcblx0cmV0dXJuIGZ1bmN0aW9uIHJlZmVycmVyUG9saWN5TWlkZGxld2FyZShfcmVxLCByZXMsIG5leHQpIHtcblx0XHRyZXMuc2V0SGVhZGVyKFwiUmVmZXJyZXItUG9saWN5XCIsIGhlYWRlclZhbHVlKVxuXHRcdG5leHQoKVxuXHR9XG59XG5cbmNvbnN0IERFRkFVTFRfTUFYX0FHRSA9IDE4MCAqIDI0ICogNjAgKiA2MFxuZnVuY3Rpb24gcGFyc2VNYXhBZ2UodmFsdWUgPSBERUZBVUxUX01BWF9BR0UpIHtcblx0aWYgKHZhbHVlID49IDAgJiYgTnVtYmVyLmlzRmluaXRlKHZhbHVlKSkge1xuXHRcdHJldHVybiBNYXRoLmZsb29yKHZhbHVlKVxuXHR9IGVsc2Uge1xuXHRcdHRocm93IG5ldyBFcnJvcihgU3RyaWN0LVRyYW5zcG9ydC1TZWN1cml0eTogJHtKU09OLnN0cmluZ2lmeSh2YWx1ZSl9IGlzIG5vdCBhIHZhbGlkIHZhbHVlIGZvciBtYXhBZ2UuIFBsZWFzZSBjaG9vc2UgYSBwb3NpdGl2ZSBpbnRlZ2VyLmApXG5cdH1cbn1cbmZ1bmN0aW9uIGdldEhlYWRlclZhbHVlRnJvbU9wdGlvbnMkMihvcHRpb25zKSB7XG5cdGlmIChcIm1heGFnZVwiIGluIG9wdGlvbnMpIHtcblx0XHR0aHJvdyBuZXcgRXJyb3IoXCJTdHJpY3QtVHJhbnNwb3J0LVNlY3VyaXR5IHJlY2VpdmVkIGFuIHVuc3VwcG9ydGVkIHByb3BlcnR5LCBgbWF4YWdlYC4gRGlkIHlvdSBtZWFuIHRvIHBhc3MgYG1heEFnZWA/XCIpXG5cdH1cblx0aWYgKFwiaW5jbHVkZVN1YmRvbWFpbnNcIiBpbiBvcHRpb25zKSB7XG5cdFx0Y29uc29sZS53YXJuKCdTdHJpY3QtVHJhbnNwb3J0LVNlY3VyaXR5IG1pZGRsZXdhcmUgc2hvdWxkIHVzZSBgaW5jbHVkZVN1YkRvbWFpbnNgIGluc3RlYWQgb2YgYGluY2x1ZGVTdWJkb21haW5zYC4gKFRoZSBjb3JyZWN0IG9uZSBoYXMgYW4gdXBwZXJjYXNlIFwiRFwiLiknKVxuXHR9XG5cdGlmIChcInNldElmXCIgaW4gb3B0aW9ucykge1xuXHRcdGNvbnNvbGUud2FybihcIlN0cmljdC1UcmFuc3BvcnQtU2VjdXJpdHkgbWlkZGxld2FyZSBubyBsb25nZXIgc3VwcG9ydHMgdGhlIGBzZXRJZmAgcGFyYW1ldGVyLiBTZWUgdGhlIGRvY3VtZW50YXRpb24gYW5kIDxodHRwczovL2dpdGh1Yi5jb20vaGVsbWV0anMvaGVsbWV0L3dpa2kvQ29uZGl0aW9uYWxseS11c2luZy1taWRkbGV3YXJlPiBpZiB5b3UgbmVlZCBoZWxwIHJlcGxpY2F0aW5nIHRoaXMgYmVoYXZpb3IuXCIpXG5cdH1cblx0Y29uc3QgZGlyZWN0aXZlcyA9IFtgbWF4LWFnZT0ke3BhcnNlTWF4QWdlKG9wdGlvbnMubWF4QWdlKX1gXVxuXHRpZiAob3B0aW9ucy5pbmNsdWRlU3ViRG9tYWlucyA9PT0gdW5kZWZpbmVkIHx8IG9wdGlvbnMuaW5jbHVkZVN1YkRvbWFpbnMpIHtcblx0XHRkaXJlY3RpdmVzLnB1c2goXCJpbmNsdWRlU3ViRG9tYWluc1wiKVxuXHR9XG5cdGlmIChvcHRpb25zLnByZWxvYWQpIHtcblx0XHRkaXJlY3RpdmVzLnB1c2goXCJwcmVsb2FkXCIpXG5cdH1cblx0cmV0dXJuIGRpcmVjdGl2ZXMuam9pbihcIjsgXCIpXG59XG5mdW5jdGlvbiBzdHJpY3RUcmFuc3BvcnRTZWN1cml0eShvcHRpb25zID0ge30pIHtcblx0Y29uc3QgaGVhZGVyVmFsdWUgPSBnZXRIZWFkZXJWYWx1ZUZyb21PcHRpb25zJDIob3B0aW9ucylcblx0cmV0dXJuIGZ1bmN0aW9uIHN0cmljdFRyYW5zcG9ydFNlY3VyaXR5TWlkZGxld2FyZShfcmVxLCByZXMsIG5leHQpIHtcblx0XHRyZXMuc2V0SGVhZGVyKFwiU3RyaWN0LVRyYW5zcG9ydC1TZWN1cml0eVwiLCBoZWFkZXJWYWx1ZSlcblx0XHRuZXh0KClcblx0fVxufVxuXG5mdW5jdGlvbiB4Q29udGVudFR5cGVPcHRpb25zKCkge1xuXHRyZXR1cm4gZnVuY3Rpb24geENvbnRlbnRUeXBlT3B0aW9uc01pZGRsZXdhcmUoX3JlcSwgcmVzLCBuZXh0KSB7XG5cdFx0cmVzLnNldEhlYWRlcihcIlgtQ29udGVudC1UeXBlLU9wdGlvbnNcIiwgXCJub3NuaWZmXCIpXG5cdFx0bmV4dCgpXG5cdH1cbn1cblxuZnVuY3Rpb24geERuc1ByZWZldGNoQ29udHJvbChvcHRpb25zID0ge30pIHtcblx0Y29uc3QgaGVhZGVyVmFsdWUgPSBvcHRpb25zLmFsbG93ID8gXCJvblwiIDogXCJvZmZcIlxuXHRyZXR1cm4gZnVuY3Rpb24geERuc1ByZWZldGNoQ29udHJvbE1pZGRsZXdhcmUoX3JlcSwgcmVzLCBuZXh0KSB7XG5cdFx0cmVzLnNldEhlYWRlcihcIlgtRE5TLVByZWZldGNoLUNvbnRyb2xcIiwgaGVhZGVyVmFsdWUpXG5cdFx0bmV4dCgpXG5cdH1cbn1cblxuZnVuY3Rpb24geERvd25sb2FkT3B0aW9ucygpIHtcblx0cmV0dXJuIGZ1bmN0aW9uIHhEb3dubG9hZE9wdGlvbnNNaWRkbGV3YXJlKF9yZXEsIHJlcywgbmV4dCkge1xuXHRcdHJlcy5zZXRIZWFkZXIoXCJYLURvd25sb2FkLU9wdGlvbnNcIiwgXCJub29wZW5cIilcblx0XHRuZXh0KClcblx0fVxufVxuXG5mdW5jdGlvbiBnZXRIZWFkZXJWYWx1ZUZyb21PcHRpb25zJDEoe2FjdGlvbiA9IFwic2FtZW9yaWdpblwifSkge1xuXHRjb25zdCBub3JtYWxpemVkQWN0aW9uID0gdHlwZW9mIGFjdGlvbiA9PT0gXCJzdHJpbmdcIiA/IGFjdGlvbi50b1VwcGVyQ2FzZSgpIDogYWN0aW9uXG5cdHN3aXRjaCAobm9ybWFsaXplZEFjdGlvbikge1xuXHRcdGNhc2UgXCJTQU1FLU9SSUdJTlwiOlxuXHRcdFx0cmV0dXJuIFwiU0FNRU9SSUdJTlwiXG5cdFx0Y2FzZSBcIkRFTllcIjpcblx0XHRjYXNlIFwiU0FNRU9SSUdJTlwiOlxuXHRcdFx0cmV0dXJuIG5vcm1hbGl6ZWRBY3Rpb25cblx0XHRkZWZhdWx0OlxuXHRcdFx0dGhyb3cgbmV3IEVycm9yKGBYLUZyYW1lLU9wdGlvbnMgcmVjZWl2ZWQgYW4gaW52YWxpZCBhY3Rpb24gJHtKU09OLnN0cmluZ2lmeShhY3Rpb24pfWApXG5cdH1cbn1cbmZ1bmN0aW9uIHhGcmFtZU9wdGlvbnMob3B0aW9ucyA9IHt9KSB7XG5cdGNvbnN0IGhlYWRlclZhbHVlID0gZ2V0SGVhZGVyVmFsdWVGcm9tT3B0aW9ucyQxKG9wdGlvbnMpXG5cdHJldHVybiBmdW5jdGlvbiB4RnJhbWVPcHRpb25zTWlkZGxld2FyZShfcmVxLCByZXMsIG5leHQpIHtcblx0XHRyZXMuc2V0SGVhZGVyKFwiWC1GcmFtZS1PcHRpb25zXCIsIGhlYWRlclZhbHVlKVxuXHRcdG5leHQoKVxuXHR9XG59XG5cbmNvbnN0IEFMTE9XRURfUEVSTUlUVEVEX1BPTElDSUVTID0gbmV3IFNldChbXCJub25lXCIsIFwibWFzdGVyLW9ubHlcIiwgXCJieS1jb250ZW50LXR5cGVcIiwgXCJhbGxcIl0pXG5mdW5jdGlvbiBnZXRIZWFkZXJWYWx1ZUZyb21PcHRpb25zKHtwZXJtaXR0ZWRQb2xpY2llcyA9IFwibm9uZVwifSkge1xuXHRpZiAoQUxMT1dFRF9QRVJNSVRURURfUE9MSUNJRVMuaGFzKHBlcm1pdHRlZFBvbGljaWVzKSkge1xuXHRcdHJldHVybiBwZXJtaXR0ZWRQb2xpY2llc1xuXHR9IGVsc2Uge1xuXHRcdHRocm93IG5ldyBFcnJvcihgWC1QZXJtaXR0ZWQtQ3Jvc3MtRG9tYWluLVBvbGljaWVzIGRvZXMgbm90IHN1cHBvcnQgJHtKU09OLnN0cmluZ2lmeShwZXJtaXR0ZWRQb2xpY2llcyl9YClcblx0fVxufVxuZnVuY3Rpb24geFBlcm1pdHRlZENyb3NzRG9tYWluUG9saWNpZXMob3B0aW9ucyA9IHt9KSB7XG5cdGNvbnN0IGhlYWRlclZhbHVlID0gZ2V0SGVhZGVyVmFsdWVGcm9tT3B0aW9ucyhvcHRpb25zKVxuXHRyZXR1cm4gZnVuY3Rpb24geFBlcm1pdHRlZENyb3NzRG9tYWluUG9saWNpZXNNaWRkbGV3YXJlKF9yZXEsIHJlcywgbmV4dCkge1xuXHRcdHJlcy5zZXRIZWFkZXIoXCJYLVBlcm1pdHRlZC1Dcm9zcy1Eb21haW4tUG9saWNpZXNcIiwgaGVhZGVyVmFsdWUpXG5cdFx0bmV4dCgpXG5cdH1cbn1cblxuZnVuY3Rpb24geFBvd2VyZWRCeSgpIHtcblx0cmV0dXJuIGZ1bmN0aW9uIHhQb3dlcmVkQnlNaWRkbGV3YXJlKF9yZXEsIHJlcywgbmV4dCkge1xuXHRcdHJlcy5yZW1vdmVIZWFkZXIoXCJYLVBvd2VyZWQtQnlcIilcblx0XHRuZXh0KClcblx0fVxufVxuXG5mdW5jdGlvbiB4WHNzUHJvdGVjdGlvbigpIHtcblx0cmV0dXJuIGZ1bmN0aW9uIHhYc3NQcm90ZWN0aW9uTWlkZGxld2FyZShfcmVxLCByZXMsIG5leHQpIHtcblx0XHRyZXMuc2V0SGVhZGVyKFwiWC1YU1MtUHJvdGVjdGlvblwiLCBcIjBcIilcblx0XHRuZXh0KClcblx0fVxufVxuXG5mdW5jdGlvbiBnZXRBcmdzKG9wdGlvbiwgbWlkZGxld2FyZUNvbmZpZyA9IHt9KSB7XG5cdHN3aXRjaCAob3B0aW9uKSB7XG5cdFx0Y2FzZSB1bmRlZmluZWQ6XG5cdFx0Y2FzZSB0cnVlOlxuXHRcdFx0cmV0dXJuIFtdXG5cdFx0Y2FzZSBmYWxzZTpcblx0XHRcdHJldHVybiBudWxsXG5cdFx0ZGVmYXVsdDpcblx0XHRcdGlmIChtaWRkbGV3YXJlQ29uZmlnLnRha2VzT3B0aW9ucyA9PT0gZmFsc2UpIHtcblx0XHRcdFx0Y29uc29sZS53YXJuKGAke21pZGRsZXdhcmVDb25maWcubmFtZX0gZG9lcyBub3QgdGFrZSBvcHRpb25zLiBSZW1vdmUgdGhlIHByb3BlcnR5IHRvIHNpbGVuY2UgdGhpcyB3YXJuaW5nLmApXG5cdFx0XHRcdHJldHVybiBbXVxuXHRcdFx0fSBlbHNlIHtcblx0XHRcdFx0cmV0dXJuIFtvcHRpb25dXG5cdFx0XHR9XG5cdH1cbn1cbmZ1bmN0aW9uIGdldE1pZGRsZXdhcmVGdW5jdGlvbnNGcm9tT3B0aW9ucyhvcHRpb25zKSB7XG5cdGNvbnN0IHJlc3VsdCA9IFtdXG5cdGNvbnN0IGNvbnRlbnRTZWN1cml0eVBvbGljeUFyZ3MgPSBnZXRBcmdzKG9wdGlvbnMuY29udGVudFNlY3VyaXR5UG9saWN5KVxuXHRpZiAoY29udGVudFNlY3VyaXR5UG9saWN5QXJncykge1xuXHRcdHJlc3VsdC5wdXNoKGNvbnRlbnRTZWN1cml0eVBvbGljeSguLi5jb250ZW50U2VjdXJpdHlQb2xpY3lBcmdzKSlcblx0fVxuXHRjb25zdCBjcm9zc09yaWdpbkVtYmVkZGVyUG9saWN5QXJncyA9IGdldEFyZ3Mob3B0aW9ucy5jcm9zc09yaWdpbkVtYmVkZGVyUG9saWN5KVxuXHRpZiAoY3Jvc3NPcmlnaW5FbWJlZGRlclBvbGljeUFyZ3MpIHtcblx0XHRyZXN1bHQucHVzaChjcm9zc09yaWdpbkVtYmVkZGVyUG9saWN5KC4uLmNyb3NzT3JpZ2luRW1iZWRkZXJQb2xpY3lBcmdzKSlcblx0fVxuXHRjb25zdCBjcm9zc09yaWdpbk9wZW5lclBvbGljeUFyZ3MgPSBnZXRBcmdzKG9wdGlvbnMuY3Jvc3NPcmlnaW5PcGVuZXJQb2xpY3kpXG5cdGlmIChjcm9zc09yaWdpbk9wZW5lclBvbGljeUFyZ3MpIHtcblx0XHRyZXN1bHQucHVzaChjcm9zc09yaWdpbk9wZW5lclBvbGljeSguLi5jcm9zc09yaWdpbk9wZW5lclBvbGljeUFyZ3MpKVxuXHR9XG5cdGNvbnN0IGNyb3NzT3JpZ2luUmVzb3VyY2VQb2xpY3lBcmdzID0gZ2V0QXJncyhvcHRpb25zLmNyb3NzT3JpZ2luUmVzb3VyY2VQb2xpY3kpXG5cdGlmIChjcm9zc09yaWdpblJlc291cmNlUG9saWN5QXJncykge1xuXHRcdHJlc3VsdC5wdXNoKGNyb3NzT3JpZ2luUmVzb3VyY2VQb2xpY3koLi4uY3Jvc3NPcmlnaW5SZXNvdXJjZVBvbGljeUFyZ3MpKVxuXHR9XG5cdGNvbnN0IHhEbnNQcmVmZXRjaENvbnRyb2xBcmdzID0gZ2V0QXJncyhvcHRpb25zLmRuc1ByZWZldGNoQ29udHJvbClcblx0aWYgKHhEbnNQcmVmZXRjaENvbnRyb2xBcmdzKSB7XG5cdFx0cmVzdWx0LnB1c2goeERuc1ByZWZldGNoQ29udHJvbCguLi54RG5zUHJlZmV0Y2hDb250cm9sQXJncykpXG5cdH1cblx0Y29uc3QgZXhwZWN0Q3RBcmdzID0gb3B0aW9ucy5leHBlY3RDdCAmJiBnZXRBcmdzKG9wdGlvbnMuZXhwZWN0Q3QpXG5cdGlmIChleHBlY3RDdEFyZ3MpIHtcblx0XHRyZXN1bHQucHVzaChleHBlY3RDdCguLi5leHBlY3RDdEFyZ3MpKVxuXHR9XG5cdGNvbnN0IHhGcmFtZU9wdGlvbnNBcmdzID0gZ2V0QXJncyhvcHRpb25zLmZyYW1lZ3VhcmQpXG5cdGlmICh4RnJhbWVPcHRpb25zQXJncykge1xuXHRcdHJlc3VsdC5wdXNoKHhGcmFtZU9wdGlvbnMoLi4ueEZyYW1lT3B0aW9uc0FyZ3MpKVxuXHR9XG5cdGNvbnN0IHhQb3dlcmVkQnlBcmdzID0gZ2V0QXJncyhvcHRpb25zLmhpZGVQb3dlcmVkQnksIHtcblx0XHRuYW1lOiBcImhpZGVQb3dlcmVkQnlcIixcblx0XHR0YWtlc09wdGlvbnM6IGZhbHNlXG5cdH0pXG5cdGlmICh4UG93ZXJlZEJ5QXJncykge1xuXHRcdHJlc3VsdC5wdXNoKHhQb3dlcmVkQnkoKSlcblx0fVxuXHRjb25zdCBzdHJpY3RUcmFuc3BvcnRTZWN1cml0eUFyZ3MgPSBnZXRBcmdzKG9wdGlvbnMuaHN0cylcblx0aWYgKHN0cmljdFRyYW5zcG9ydFNlY3VyaXR5QXJncykge1xuXHRcdHJlc3VsdC5wdXNoKHN0cmljdFRyYW5zcG9ydFNlY3VyaXR5KC4uLnN0cmljdFRyYW5zcG9ydFNlY3VyaXR5QXJncykpXG5cdH1cblx0Y29uc3QgeERvd25sb2FkT3B0aW9uc0FyZ3MgPSBnZXRBcmdzKG9wdGlvbnMuaWVOb09wZW4sIHtcblx0XHRuYW1lOiBcImllTm9PcGVuXCIsXG5cdFx0dGFrZXNPcHRpb25zOiBmYWxzZVxuXHR9KVxuXHRpZiAoeERvd25sb2FkT3B0aW9uc0FyZ3MpIHtcblx0XHRyZXN1bHQucHVzaCh4RG93bmxvYWRPcHRpb25zKCkpXG5cdH1cblx0Y29uc3QgeENvbnRlbnRUeXBlT3B0aW9uc0FyZ3MgPSBnZXRBcmdzKG9wdGlvbnMubm9TbmlmZiwge1xuXHRcdG5hbWU6IFwibm9TbmlmZlwiLFxuXHRcdHRha2VzT3B0aW9uczogZmFsc2Vcblx0fSlcblx0aWYgKHhDb250ZW50VHlwZU9wdGlvbnNBcmdzKSB7XG5cdFx0cmVzdWx0LnB1c2goeENvbnRlbnRUeXBlT3B0aW9ucygpKVxuXHR9XG5cdGNvbnN0IG9yaWdpbkFnZW50Q2x1c3RlckFyZ3MgPSBnZXRBcmdzKG9wdGlvbnMub3JpZ2luQWdlbnRDbHVzdGVyLCB7XG5cdFx0bmFtZTogXCJvcmlnaW5BZ2VudENsdXN0ZXJcIixcblx0XHR0YWtlc09wdGlvbnM6IGZhbHNlXG5cdH0pXG5cdGlmIChvcmlnaW5BZ2VudENsdXN0ZXJBcmdzKSB7XG5cdFx0cmVzdWx0LnB1c2gob3JpZ2luQWdlbnRDbHVzdGVyKCkpXG5cdH1cblx0Y29uc3QgeFBlcm1pdHRlZENyb3NzRG9tYWluUG9saWNpZXNBcmdzID0gZ2V0QXJncyhvcHRpb25zLnBlcm1pdHRlZENyb3NzRG9tYWluUG9saWNpZXMpXG5cdGlmICh4UGVybWl0dGVkQ3Jvc3NEb21haW5Qb2xpY2llc0FyZ3MpIHtcblx0XHRyZXN1bHQucHVzaCh4UGVybWl0dGVkQ3Jvc3NEb21haW5Qb2xpY2llcyguLi54UGVybWl0dGVkQ3Jvc3NEb21haW5Qb2xpY2llc0FyZ3MpKVxuXHR9XG5cdGNvbnN0IHJlZmVycmVyUG9saWN5QXJncyA9IGdldEFyZ3Mob3B0aW9ucy5yZWZlcnJlclBvbGljeSlcblx0aWYgKHJlZmVycmVyUG9saWN5QXJncykge1xuXHRcdHJlc3VsdC5wdXNoKHJlZmVycmVyUG9saWN5KC4uLnJlZmVycmVyUG9saWN5QXJncykpXG5cdH1cblx0Y29uc3QgeFhzc1Byb3RlY3Rpb25BcmdzID0gZ2V0QXJncyhvcHRpb25zLnhzc0ZpbHRlciwge1xuXHRcdG5hbWU6IFwieHNzRmlsdGVyXCIsXG5cdFx0dGFrZXNPcHRpb25zOiBmYWxzZVxuXHR9KVxuXHRpZiAoeFhzc1Byb3RlY3Rpb25BcmdzKSB7XG5cdFx0cmVzdWx0LnB1c2goeFhzc1Byb3RlY3Rpb24oKSlcblx0fVxuXHRyZXR1cm4gcmVzdWx0XG59XG5jb25zdCBoZWxtZXQgPSBPYmplY3QuYXNzaWduKFxuXHRmdW5jdGlvbiBoZWxtZXQob3B0aW9ucyA9IHt9KSB7XG5cdFx0dmFyIF9hXG5cdFx0Ly8gUGVvcGxlIHNob3VsZCBiZSBhYmxlIHRvIHBhc3MgYW4gb3B0aW9ucyBvYmplY3Qgd2l0aCBubyBwcm90b3R5cGUsXG5cdFx0Ly8gc28gd2Ugd2FudCB0aGlzIG9wdGlvbmFsIGNoYWluaW5nLlxuXHRcdC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBAdHlwZXNjcmlwdC1lc2xpbnQvbm8tdW5uZWNlc3NhcnktY29uZGl0aW9uXG5cdFx0aWYgKCgoX2EgPSBvcHRpb25zLmNvbnN0cnVjdG9yKSA9PT0gbnVsbCB8fCBfYSA9PT0gdm9pZCAwID8gdm9pZCAwIDogX2EubmFtZSkgPT09IFwiSW5jb21pbmdNZXNzYWdlXCIpIHtcblx0XHRcdHRocm93IG5ldyBFcnJvcihcIkl0IGFwcGVhcnMgeW91IGhhdmUgZG9uZSBzb21ldGhpbmcgbGlrZSBgYXBwLnVzZShoZWxtZXQpYCwgYnV0IGl0IHNob3VsZCBiZSBgYXBwLnVzZShoZWxtZXQoKSlgLlwiKVxuXHRcdH1cblx0XHRjb25zdCBtaWRkbGV3YXJlRnVuY3Rpb25zID0gZ2V0TWlkZGxld2FyZUZ1bmN0aW9uc0Zyb21PcHRpb25zKG9wdGlvbnMpXG5cdFx0cmV0dXJuIGZ1bmN0aW9uIGhlbG1ldE1pZGRsZXdhcmUocmVxLCByZXMsIG5leHQpIHtcblx0XHRcdGxldCBtaWRkbGV3YXJlSW5kZXggPSAwXG5cdFx0XHQ7KGZ1bmN0aW9uIGludGVybmFsTmV4dChlcnIpIHtcblx0XHRcdFx0aWYgKGVycikge1xuXHRcdFx0XHRcdG5leHQoZXJyKVxuXHRcdFx0XHRcdHJldHVyblxuXHRcdFx0XHR9XG5cdFx0XHRcdGNvbnN0IG1pZGRsZXdhcmVGdW5jdGlvbiA9IG1pZGRsZXdhcmVGdW5jdGlvbnNbbWlkZGxld2FyZUluZGV4XVxuXHRcdFx0XHRpZiAobWlkZGxld2FyZUZ1bmN0aW9uKSB7XG5cdFx0XHRcdFx0bWlkZGxld2FyZUluZGV4Kytcblx0XHRcdFx0XHRtaWRkbGV3YXJlRnVuY3Rpb24ocmVxLCByZXMsIGludGVybmFsTmV4dClcblx0XHRcdFx0fSBlbHNlIHtcblx0XHRcdFx0XHRuZXh0KClcblx0XHRcdFx0fVxuXHRcdFx0fSkoKVxuXHRcdH1cblx0fSxcblx0e1xuXHRcdGNvbnRlbnRTZWN1cml0eVBvbGljeSxcblx0XHRjcm9zc09yaWdpbkVtYmVkZGVyUG9saWN5LFxuXHRcdGNyb3NzT3JpZ2luT3BlbmVyUG9saWN5LFxuXHRcdGNyb3NzT3JpZ2luUmVzb3VyY2VQb2xpY3ksXG5cdFx0ZG5zUHJlZmV0Y2hDb250cm9sOiB4RG5zUHJlZmV0Y2hDb250cm9sLFxuXHRcdGV4cGVjdEN0LFxuXHRcdGZyYW1lZ3VhcmQ6IHhGcmFtZU9wdGlvbnMsXG5cdFx0aGlkZVBvd2VyZWRCeTogeFBvd2VyZWRCeSxcblx0XHRoc3RzOiBzdHJpY3RUcmFuc3BvcnRTZWN1cml0eSxcblx0XHRpZU5vT3BlbjogeERvd25sb2FkT3B0aW9ucyxcblx0XHRub1NuaWZmOiB4Q29udGVudFR5cGVPcHRpb25zLFxuXHRcdG9yaWdpbkFnZW50Q2x1c3Rlcixcblx0XHRwZXJtaXR0ZWRDcm9zc0RvbWFpblBvbGljaWVzOiB4UGVybWl0dGVkQ3Jvc3NEb21haW5Qb2xpY2llcyxcblx0XHRyZWZlcnJlclBvbGljeSxcblx0XHR4c3NGaWx0ZXI6IHhYc3NQcm90ZWN0aW9uXG5cdH1cbilcblxuZXhwb3J0IHtjb250ZW50U2VjdXJpdHlQb2xpY3ksIGNyb3NzT3JpZ2luRW1iZWRkZXJQb2xpY3ksIGNyb3NzT3JpZ2luT3BlbmVyUG9saWN5LCBjcm9zc09yaWdpblJlc291cmNlUG9saWN5LCBoZWxtZXQgYXMgZGVmYXVsdCwgeERuc1ByZWZldGNoQ29udHJvbCBhcyBkbnNQcmVmZXRjaENvbnRyb2wsIGV4cGVjdEN0LCB4RnJhbWVPcHRpb25zIGFzIGZyYW1lZ3VhcmQsIHhQb3dlcmVkQnkgYXMgaGlkZVBvd2VyZWRCeSwgc3RyaWN0VHJhbnNwb3J0U2VjdXJpdHkgYXMgaHN0cywgeERvd25sb2FkT3B0aW9ucyBhcyBpZU5vT3BlbiwgeENvbnRlbnRUeXBlT3B0aW9ucyBhcyBub1NuaWZmLCBvcmlnaW5BZ2VudENsdXN0ZXIsIHhQZXJtaXR0ZWRDcm9zc0RvbWFpblBvbGljaWVzIGFzIHBlcm1pdHRlZENyb3NzRG9tYWluUG9saWNpZXMsIHJlZmVycmVyUG9saWN5LCB4WHNzUHJvdGVjdGlvbiBhcyB4c3NGaWx0ZXJ9XG4iLCIvLyBnbG9iYWxcbmV4cG9ydCBjb25zdCBJTlRFUk5BTF9TRVJWRVIgPSAn0JLQuNC90LjQutC70LAg0L/QvtC80LjQu9C60LAnO1xuZXhwb3J0IGNvbnN0IElOVkFMSURfREFUQSA9ICfQndC10LrQvtGA0LXQutGC0L3RliDQtNCw0L3Rlic7XG4vLyBkYXRhXG5leHBvcnQgY29uc3QgTk9UX0ZPVU5EID0gJ9Ce0LFg0ZTQutGCINC90LUg0LfQvdCw0LnQtNC10L3Qvic7XG4vLyBsb2dpblxuZXhwb3J0IGNvbnN0IExPR0lOID0gJ9Cd0LXQv9GA0LDQstC40LvRjNC90LjQuSDQu9C+0LPRltC9INCw0LHQviDQv9Cw0YDQvtC70YwnO1xuIiwiLy8gMjAwXG5leHBvcnQgY29uc3QgT0sgPSAyMDA7XG5leHBvcnQgY29uc3QgQ1JFQVRFRCA9IDIwMTtcbmV4cG9ydCBjb25zdCBBQ0NFUFRFRCA9IDIwMjtcbmV4cG9ydCBjb25zdCBOT19DT05URU5UID0gMjA0O1xuLy8gNDAwXG5leHBvcnQgY29uc3QgQkFEX1JFUVVFU1QgPSA0MDA7XG5leHBvcnQgY29uc3QgVU5BVVRIT1JJWkVEID0gNDAxO1xuZXhwb3J0IGNvbnN0IEZPUkJJRERFTiA9IDQwMztcbmV4cG9ydCBjb25zdCBOT1RfRk9VTkQgPSA0MDQ7XG5leHBvcnQgY29uc3QgTUVUSE9EX05PVF9BTExPV0VEID0gNDA1O1xuZXhwb3J0IGNvbnN0IE5PVF9BQ0NFUFRBQkxFID0gNDA2O1xuZXhwb3J0IGNvbnN0IFJFUVVFU1RfVElNRU9VVCA9IDQwODtcbmV4cG9ydCBjb25zdCBDT05GTElDVCA9IDQwOTtcbmV4cG9ydCBjb25zdCBQQVlMT0FEX1RPT19MQVJHRSA9IDQxMztcbmV4cG9ydCBjb25zdCBVUklfVE9PX0xPTkcgPSA0MTQ7XG5leHBvcnQgY29uc3QgVU5TVVBQT1JURURfTUVESUFfVFlQRSA9IDQxNTtcbmV4cG9ydCBjb25zdCBSQU5HRV9OT1RfU0FUSVNGSUFCTEUgPSA0MTY7XG5leHBvcnQgY29uc3QgVE9PX01BTllfUkVRVUVTVFMgPSA0Mjk7XG5leHBvcnQgY29uc3QgUkVRVUVTVF9IRUFERVJfRklFTERTX1RPT19MQVJHRSA9IDQzMTtcbmV4cG9ydCBjb25zdCBVTkFWQUlMQUJMRV9GT1JfTEVHQUxfUkVBU09OUyA9IDQ1MTtcbi8vIDUwMFxuZXhwb3J0IGNvbnN0IElOVEVSTkFMX1NFUlZFUl9FUlJPUiA9IDUwMDtcbmV4cG9ydCBjb25zdCBOT1RfSU1QTEVNRU5URUQgPSA1MDE7XG5leHBvcnQgY29uc3QgQkFEX0dBVEVXQVkgPSA1MDI7XG5leHBvcnQgY29uc3QgU0VSVklDRV9VTkFWQUlMQUJMRSA9IDUwMztcbmV4cG9ydCBjb25zdCBHQVRFV0FZX1RJTUVPVVQgPSA1MDQ7XG5leHBvcnQgY29uc3QgTE9PUF9ERVRFQ1RFRCA9IDUwODtcbmV4cG9ydCBjb25zdCBORVRXT1JLX0FVVEhFTlRJQ0FUSU9OX1JFUVVJUkVEID0gNTExO1xuIiwiaW1wb3J0ICogYXMgRVJST1IgZnJvbSAnLi9lcnJvck1lc3NhZ2VzJztcbmltcG9ydCAqIGFzIFNUQVRVUyBmcm9tICcuL3N0YXR1c0NvZGVzJztcbmV4cG9ydCBjbGFzcyBBcGlFcnJvciB7XG4gICAgc3RhdHVzO1xuICAgIG1lc3NhZ2U7XG4gICAgZXJyb3I7XG4gICAgY29uc3RydWN0b3IocGFyYW1zKSB7XG4gICAgICAgIGNvbnN0IHsgc3RhdHVzLCBtZXNzYWdlLCBlcnJvciB9ID0gcGFyYW1zO1xuICAgICAgICB0aGlzLnN0YXR1cyA9IHN0YXR1cztcbiAgICAgICAgdGhpcy5tZXNzYWdlID0gbWVzc2FnZTtcbiAgICAgICAgdGhpcy5lcnJvciA9IGVycm9yID8/ICcnO1xuICAgIH1cbiAgICBzdGF0aWMgaW50ZXJuYWxTZXJ2ZXJFcnJvcihlcnJvcikge1xuICAgICAgICByZXR1cm4gbmV3IEFwaUVycm9yKHtcbiAgICAgICAgICAgIHN0YXR1czogU1RBVFVTLklOVEVSTkFMX1NFUlZFUl9FUlJPUixcbiAgICAgICAgICAgIG1lc3NhZ2U6IEVSUk9SLklOVEVSTkFMX1NFUlZFUixcbiAgICAgICAgICAgIGVycm9yLFxuICAgICAgICB9KTtcbiAgICB9XG4gICAgLy8gVE9ETyBpbXBsZW1lbnRcbiAgICBub3RpZnkoKSB7IH1cbn1cbiIsImV4cG9ydCBjbGFzcyBBcGlTdWNjZXNzIHtcbiAgICBzdGF0dXM7XG4gICAgbWVzc2FnZTtcbiAgICBkYXRhO1xuICAgIGNvbnN0cnVjdG9yKHBhcmFtcykge1xuICAgICAgICBjb25zdCB7IHN0YXR1cywgbWVzc2FnZSwgZGF0YSB9ID0gcGFyYW1zO1xuICAgICAgICB0aGlzLnN0YXR1cyA9IHN0YXR1cztcbiAgICAgICAgdGhpcy5tZXNzYWdlID0gbWVzc2FnZTtcbiAgICAgICAgdGhpcy5kYXRhID0gZGF0YTtcbiAgICB9XG59XG4iLCJpbXBvcnQgeyBTY2hlbWEsIG1vZGVsLCBtb2RlbHMgfSBmcm9tICdtb25nb29zZSc7XG5jb25zdCBMYWJTY2hlbWEgPSBuZXcgU2NoZW1hKHtcbiAgICBuYW1lOiB7XG4gICAgICAgIHR5cGU6IFN0cmluZyxcbiAgICAgICAgcmVxdWlyZWQ6IHRydWUsXG4gICAgfSxcbiAgICByYXRpbmc6IHtcbiAgICAgICAgdHlwZTogTnVtYmVyLFxuICAgICAgICByZXF1aXJlZDogdHJ1ZSxcbiAgICB9LFxuICAgIG1lc3NhZ2U6IHtcbiAgICAgICAgdHlwZTogU3RyaW5nLFxuICAgICAgICByZXF1aXJlZDogdHJ1ZSxcbiAgICB9LFxufSk7XG5leHBvcnQgY29uc3QgRGlzY2lwbGluZVNjaGVtYSA9IG5ldyBTY2hlbWEoe1xuICAgIG5hbWU6IHtcbiAgICAgICAgdHlwZTogU3RyaW5nLFxuICAgICAgICByZXF1aXJlZDogdHJ1ZSxcbiAgICB9LFxuICAgIHRlYWNoZXI6IHtcbiAgICAgICAgdHlwZTogU3RyaW5nLFxuICAgICAgICByZXF1aXJlZDogdHJ1ZSxcbiAgICB9LFxuICAgIHRlYWNoZXJFbWFpbDoge1xuICAgICAgICB0eXBlOiBTdHJpbmcsXG4gICAgICAgIHJlcXVpcmVkOiB0cnVlLFxuICAgIH0sXG4gICAgbGFiczoge1xuICAgICAgICB0eXBlOiBbTGFiU2NoZW1hXSxcbiAgICAgICAgcmVxdWlyZWQ6IHRydWUsXG4gICAgfSxcbn0pO1xuY29uc3QgU3BlY2lhbGl0aWVTY2hlbWEgPSBuZXcgU2NoZW1hKHtcbiAgICBpZDoge1xuICAgICAgICB0eXBlOiBTdHJpbmcsXG4gICAgICAgIHJlcXVpcmVkOiB0cnVlLFxuICAgIH0sXG4gICAgbmFtZToge1xuICAgICAgICB0eXBlOiBTdHJpbmcsXG4gICAgICAgIHJlcXVpcmVkOiB0cnVlLFxuICAgIH0sXG4gICAgZGlzY2lwbGluZXM6IHtcbiAgICAgICAgdHlwZTogW0Rpc2NpcGxpbmVTY2hlbWFdLFxuICAgICAgICByZXF1aXJlZDogdHJ1ZSxcbiAgICB9LFxufSk7XG5jb25zdCBVbml2ZXJzaXR5U2NoZW1hID0gbmV3IFNjaGVtYSh7XG4gICAgX2lkOiB7XG4gICAgICAgIHR5cGU6IE51bWJlcixcbiAgICAgICAgcmVxdWlyZWQ6IHRydWUsXG4gICAgfSxcbiAgICBpZDoge1xuICAgICAgICB0eXBlOiBTdHJpbmcsXG4gICAgICAgIHJlcXVpcmVkOiB0cnVlLFxuICAgIH0sXG4gICAgbmFtZToge1xuICAgICAgICB0eXBlOiBTdHJpbmcsXG4gICAgICAgIHJlcXVpcmVkOiB0cnVlLFxuICAgIH0sXG4gICAgYWJicjoge1xuICAgICAgICB0eXBlOiBTdHJpbmcsXG4gICAgICAgIHJlcXVpcmVkOiB0cnVlLFxuICAgIH0sXG4gICAgc3BlY2lhbGl0aWVzOiB7XG4gICAgICAgIHR5cGU6IFtTcGVjaWFsaXRpZVNjaGVtYV0sXG4gICAgICAgIHJlcXVpcmVkOiB0cnVlLFxuICAgIH0sXG59KTtcbmV4cG9ydCBjb25zdCBVbml2ZXJzaXR5TW9kZWwgPSBtb2RlbHMuVW5pdmVyc2l0eSA/PyBtb2RlbCgnVW5pdmVyc2l0eScsIFVuaXZlcnNpdHlTY2hlbWEpO1xuIiwiaW1wb3J0IHsgU2NoZW1hLCBtb2RlbCwgbW9kZWxzIH0gZnJvbSAnbW9uZ29vc2UnO1xuaW1wb3J0IHsgRGlzY2lwbGluZVNjaGVtYSB9IGZyb20gJy4vVW5pdmVyc2l0eSc7XG5jb25zdCBVc2VyU2NoZW1hID0gbmV3IFNjaGVtYSh7XG4gICAgZW1haWw6IHtcbiAgICAgICAgdHlwZTogU3RyaW5nLFxuICAgICAgICByZXF1aXJlZDogZmFsc2UsXG4gICAgICAgIGRlZmF1bHQ6ICcnLFxuICAgIH0sXG4gICAgcGFzc3dvcmQ6IHtcbiAgICAgICAgdHlwZTogU3RyaW5nLFxuICAgICAgICByZXF1aXJlZDogZmFsc2UsXG4gICAgICAgIGRlZmF1bHQ6ICcnLFxuICAgIH0sXG4gICAgbmFtZToge1xuICAgICAgICB0eXBlOiBTdHJpbmcsXG4gICAgICAgIHJlcXVpcmVkOiBmYWxzZSxcbiAgICAgICAgZGVmYXVsdDogJycsXG4gICAgfSxcbiAgICBwZXJtczoge1xuICAgICAgICB0eXBlOiBTdHJpbmcsXG4gICAgICAgIHJlcXVpcmVkOiB0cnVlLFxuICAgIH0sXG4gICAgdW5pdmVyc2l0eV9pZDoge1xuICAgICAgICB0eXBlOiBTdHJpbmcsXG4gICAgICAgIHJlcXVpcmVkOiBmYWxzZSxcbiAgICAgICAgZGVmYXVsdDogJycsXG4gICAgfSxcbiAgICBzcGVjaWFsaXR5X2lkOiB7XG4gICAgICAgIHR5cGU6IFN0cmluZyxcbiAgICAgICAgcmVxdWlyZWQ6IGZhbHNlLFxuICAgICAgICBkZWZhdWx0OiAnJyxcbiAgICB9LFxuICAgIGRpc2NpcGxpbmVzOiB7XG4gICAgICAgIHR5cGU6IFtEaXNjaXBsaW5lU2NoZW1hXSxcbiAgICAgICAgcmVxdWlyZWQ6IGZhbHNlLFxuICAgICAgICBkZWZhdWx0OiBbXSxcbiAgICB9LFxufSk7XG5Vc2VyU2NoZW1hLm1ldGhvZHMuaXNQYXNzd29yZENvcnJlY3QgPSBhc3luYyBmdW5jdGlvbiAocGFzc3dvcmQpIHtcbiAgICByZXR1cm4gdGhpcy5wYXNzd29yZCA9PT0gcGFzc3dvcmQ7XG59O1xuZXhwb3J0IGNvbnN0IFVzZXJNb2RlbCA9IG1vZGVscy5Vc2VyID8/IG1vZGVsKCdVc2VyJywgVXNlclNjaGVtYSk7XG4iLCJpbXBvcnQgeyBBcGlFcnJvciwgQXBpU3VjY2VzcywgU1RBVFVTIH0gZnJvbSAnQC9hcGkvcmVzcG9uc2VzJztcbmltcG9ydCB7IFVzZXJNb2RlbCB9IGZyb20gJ0AvRGF0YWJhc2UvbW9kZWxzL1VzZXInO1xuZXhwb3J0IGNvbnN0IHBvc3QgPSBhc3luYyAocmVxLCByZXMpID0+IHtcbiAgICB0cnkge1xuICAgICAgICBjb25zdCB7IGVtYWlsLCBwYXNzd29yZCB9ID0gcmVxLmJvZHk7XG4gICAgICAgIGlmIChlbWFpbCA9PT0gdW5kZWZpbmVkIHx8IHBhc3N3b3JkID09PSB1bmRlZmluZWQpIHtcbiAgICAgICAgICAgIGNvbnN0IHJlc3BvbnNlID0gbmV3IEFwaUVycm9yKHtcbiAgICAgICAgICAgICAgICBzdGF0dXM6IFNUQVRVUy5CQURfUkVRVUVTVCxcbiAgICAgICAgICAgICAgICBtZXNzYWdlOiAnTWlzc2luZyByZXF1aXJlZCBmaWVsZHMnLFxuICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICByZXR1cm4gcmVzLnN0YXR1cyhyZXNwb25zZS5zdGF0dXMpLnNlbmQocmVzcG9uc2UpO1xuICAgICAgICB9XG4gICAgICAgIGNvbnN0IHVzZXIgPSBhd2FpdCBVc2VyTW9kZWwuZmluZE9uZSh7IGVtYWlsIH0pO1xuICAgICAgICBjb25zdCBpc1Bhc3N3b3JkQ29ycmVjdCA9IGF3YWl0IHVzZXIuaXNQYXNzd29yZENvcnJlY3QocGFzc3dvcmQpO1xuICAgICAgICBpZiAoIWlzUGFzc3dvcmRDb3JyZWN0KSB7XG4gICAgICAgICAgICBjb25zdCByZXNwb25zZSA9IG5ldyBBcGlFcnJvcih7XG4gICAgICAgICAgICAgICAgc3RhdHVzOiBTVEFUVVMuVU5BVVRIT1JJWkVELFxuICAgICAgICAgICAgICAgIG1lc3NhZ2U6ICdFbWFpbCBvciBwYXNzd29yZCBpcyBpbmNvcnJlY3QnLFxuICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICByZXR1cm4gcmVzLnN0YXR1cyhyZXNwb25zZS5zdGF0dXMpLnNlbmQocmVzcG9uc2UpO1xuICAgICAgICB9XG4gICAgICAgIGNvbnN0IHJlc3BvbnNlID0gbmV3IEFwaVN1Y2Nlc3Moe1xuICAgICAgICAgICAgc3RhdHVzOiBTVEFUVVMuT0ssXG4gICAgICAgICAgICBtZXNzYWdlOiAnU3VjY2VzcycsXG4gICAgICAgICAgICBkYXRhOiB1c2VyLFxuICAgICAgICB9KTtcbiAgICAgICAgcmV0dXJuIHJlcy5zdGF0dXMocmVzcG9uc2Uuc3RhdHVzKS5zZW5kKHJlc3BvbnNlKTtcbiAgICB9XG4gICAgY2F0Y2ggKGVycm9yKSB7XG4gICAgICAgIGNvbnN0IHJlc3BvbnNlID0gQXBpRXJyb3IuaW50ZXJuYWxTZXJ2ZXJFcnJvcihlcnJvcik7XG4gICAgICAgIHJldHVybiByZXMuc3RhdHVzKHJlc3BvbnNlLnN0YXR1cykuc2VuZChyZXNwb25zZSk7XG4gICAgfVxuICAgIGZpbmFsbHkge1xuICAgICAgICByZXMuZW5kKCk7XG4gICAgfVxufTtcbiIsImltcG9ydCB7IFJvdXRlciB9IGZyb20gJ2V4cHJlc3MnO1xuaW1wb3J0IHsgcG9zdCB9IGZyb20gJ0AvYXBpL2NvbnRyb2xsZXJzL2xvZ2luJztcbmNvbnN0IGxvZ2luUm91dGVyID0gUm91dGVyKCk7XG5sb2dpblJvdXRlci5wb3N0KCcvJywgcG9zdCk7XG5leHBvcnQgeyBsb2dpblJvdXRlciB9O1xuIiwiaW1wb3J0IHsgQXBpRXJyb3IsIEFwaVN1Y2Nlc3MsIFNUQVRVUyB9IGZyb20gJ0AvYXBpL3Jlc3BvbnNlcyc7XG5pbXBvcnQgeyBVbml2ZXJzaXR5TW9kZWwgfSBmcm9tICdAL0RhdGFiYXNlL21vZGVscyc7XG5leHBvcnQgY29uc3QgZ2V0ID0gYXN5bmMgKHJlcSwgcmVzKSA9PiB7XG4gICAgdHJ5IHtcbiAgICAgICAgY29uc3QgeyBpZCwgYWJiciB9ID0gcmVxLmJvZHk7XG4gICAgICAgIGNvbnN0IGRhdGEgPSBhd2FpdCAoYXN5bmMgKCkgPT4ge1xuICAgICAgICAgICAgaWYgKGlkICE9PSB1bmRlZmluZWQpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gYXdhaXQgVW5pdmVyc2l0eU1vZGVsLmZpbmQoeyBpZCB9KS5sZWFuKCk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBpZiAoYWJiciAhPT0gdW5kZWZpbmVkKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIGF3YWl0IFVuaXZlcnNpdHlNb2RlbC5maW5kKHsgYWJiciB9KS5sZWFuKCk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICByZXR1cm4gYXdhaXQgVW5pdmVyc2l0eU1vZGVsLmZpbmQoKS5sZWFuKCk7XG4gICAgICAgIH0pKCk7XG4gICAgICAgIGNvbnN0IHJlc3BvbnNlID0gbmV3IEFwaVN1Y2Nlc3Moe1xuICAgICAgICAgICAgc3RhdHVzOiBTVEFUVVMuT0ssXG4gICAgICAgICAgICBtZXNzYWdlOiAnU3VjY2VzcycsXG4gICAgICAgICAgICBkYXRhLFxuICAgICAgICB9KTtcbiAgICAgICAgcmV0dXJuIHJlcy5zdGF0dXMocmVzcG9uc2Uuc3RhdHVzKS5zZW5kKHJlc3BvbnNlKTtcbiAgICB9XG4gICAgY2F0Y2ggKGVycm9yKSB7XG4gICAgICAgIGNvbnN0IHJlc3BvbnNlID0gQXBpRXJyb3IuaW50ZXJuYWxTZXJ2ZXJFcnJvcihlcnJvcik7XG4gICAgICAgIHJldHVybiByZXMuc3RhdHVzKHJlc3BvbnNlLnN0YXR1cykuc2VuZChyZXNwb25zZSk7XG4gICAgfVxuICAgIGZpbmFsbHkge1xuICAgICAgICByZXMuZW5kKCk7XG4gICAgfVxufTtcbiIsImltcG9ydCB7IFJvdXRlciB9IGZyb20gJ2V4cHJlc3MnO1xuaW1wb3J0IHsgZ2V0IH0gZnJvbSAnQC9hcGkvY29udHJvbGxlcnMvdW5pdmVyc2l0eSc7XG5jb25zdCB1bml2ZXJzaXR5Um91dGVyID0gUm91dGVyKCk7XG51bml2ZXJzaXR5Um91dGVyLmdldCgnLycsIGdldCk7XG5leHBvcnQgeyB1bml2ZXJzaXR5Um91dGVyIH07XG4iLCJpbXBvcnQgeyBBcGlFcnJvciwgQXBpU3VjY2VzcywgU1RBVFVTIH0gZnJvbSAnQC9hcGkvcmVzcG9uc2VzJztcbmltcG9ydCB7IFVzZXJNb2RlbCB9IGZyb20gJ0AvRGF0YWJhc2UvbW9kZWxzL1VzZXInO1xuZXhwb3J0IGNvbnN0IGdldCA9IGFzeW5jIChyZXEsIHJlcykgPT4ge1xuICAgIHRyeSB7XG4gICAgICAgIGNvbnN0IHsgdGVhY2hlckVtYWlsIH0gPSByZXEuYm9keTtcbiAgICAgICAgaWYgKHRlYWNoZXJFbWFpbCA9PT0gdW5kZWZpbmVkKSB7XG4gICAgICAgICAgICBjb25zdCByZXNwb25zZSA9IG5ldyBBcGlFcnJvcih7XG4gICAgICAgICAgICAgICAgc3RhdHVzOiBTVEFUVVMuQkFEX1JFUVVFU1QsXG4gICAgICAgICAgICAgICAgbWVzc2FnZTogJ01pc3NpbmcgcmVxdWlyZWQgZmllbGRzJyxcbiAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgcmV0dXJuIHJlcy5zdGF0dXMocmVzcG9uc2Uuc3RhdHVzKS5zZW5kKHJlc3BvbnNlKTtcbiAgICAgICAgfVxuICAgICAgICBjb25zdCBzdHVkZW50cyA9IGF3YWl0IFVzZXJNb2RlbC5maW5kKHtcbiAgICAgICAgICAgIGRpc2NpcGxpbmVzOiB7ICRlbGVtTWF0Y2g6IHsgdGVhY2hlckVtYWlsIH0gfSxcbiAgICAgICAgfSkubGVhbigpO1xuICAgICAgICBjb25zdCByZXNwb25zZSA9IG5ldyBBcGlTdWNjZXNzKHtcbiAgICAgICAgICAgIHN0YXR1czogU1RBVFVTLk9LLFxuICAgICAgICAgICAgbWVzc2FnZTogJ1N1Y2Nlc3MnLFxuICAgICAgICAgICAgZGF0YTogc3R1ZGVudHMsXG4gICAgICAgIH0pO1xuICAgICAgICByZXR1cm4gcmVzLnN0YXR1cyhyZXNwb25zZS5zdGF0dXMpLnNlbmQocmVzcG9uc2UpO1xuICAgIH1cbiAgICBjYXRjaCAoZXJyb3IpIHtcbiAgICAgICAgY29uc3QgcmVzcG9uc2UgPSBBcGlFcnJvci5pbnRlcm5hbFNlcnZlckVycm9yKGVycm9yKTtcbiAgICAgICAgcmV0dXJuIHJlcy5zdGF0dXMocmVzcG9uc2Uuc3RhdHVzKS5zZW5kKHJlc3BvbnNlKTtcbiAgICB9XG4gICAgZmluYWxseSB7XG4gICAgICAgIHJlcy5lbmQoKTtcbiAgICB9XG59O1xuIiwiaW1wb3J0IHsgQXBpRXJyb3IsIEFwaVN1Y2Nlc3MsIFNUQVRVUyB9IGZyb20gJ0AvYXBpL3Jlc3BvbnNlcyc7XG5pbXBvcnQgeyBVc2VyTW9kZWwgfSBmcm9tICdAL0RhdGFiYXNlL21vZGVscy9Vc2VyJztcbmV4cG9ydCBjb25zdCBwdXQgPSBhc3luYyAocmVxLCByZXMpID0+IHtcbiAgICB0cnkge1xuICAgICAgICBjb25zdCB7IHN0dWRlbnRFbWFpbCwgdGVhY2hlckVtYWlsLCBsYWJOYW1lLCByYXRpbmcsIG1lc3NhZ2UsIHBvaW50cyB9ID0gcmVxLmJvZHk7XG4gICAgICAgIGlmIChzdHVkZW50RW1haWwgPT09IHVuZGVmaW5lZCB8fFxuICAgICAgICAgICAgdGVhY2hlckVtYWlsID09PSB1bmRlZmluZWQgfHxcbiAgICAgICAgICAgIGxhYk5hbWUgPT09IHVuZGVmaW5lZCB8fFxuICAgICAgICAgICAgcmF0aW5nID09PSB1bmRlZmluZWQgfHxcbiAgICAgICAgICAgIG1lc3NhZ2UgPT09IHVuZGVmaW5lZCB8fFxuICAgICAgICAgICAgcG9pbnRzID09PSB1bmRlZmluZWQpIHtcbiAgICAgICAgICAgIGNvbnN0IHJlc3BvbnNlID0gbmV3IEFwaUVycm9yKHtcbiAgICAgICAgICAgICAgICBzdGF0dXM6IFNUQVRVUy5CQURfUkVRVUVTVCxcbiAgICAgICAgICAgICAgICBtZXNzYWdlOiAnTWlzc2luZyByZXF1aXJlZCBmaWVsZHMnLFxuICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICByZXR1cm4gcmVzLnN0YXR1cyhyZXNwb25zZS5zdGF0dXMpLnNlbmQocmVzcG9uc2UpO1xuICAgICAgICB9XG4gICAgICAgIGNvbnN0IHVwZGF0ZWRTdHVkZW50ID0gYXdhaXQgVXNlck1vZGVsLmZpbmRPbmVBbmRVcGRhdGUoe1xuICAgICAgICAgICAgZW1haWw6IHN0dWRlbnRFbWFpbCxcbiAgICAgICAgICAgICdkaXNjaXBsaW5lcy50ZWFjaGVyRW1haWwnOiB0ZWFjaGVyRW1haWwsXG4gICAgICAgICAgICAnZGlzY2lwbGluZXMubGFicy5uYW1lJzogbGFiTmFtZSxcbiAgICAgICAgfSwge1xuICAgICAgICAgICAgJHNldDoge1xuICAgICAgICAgICAgICAgICdkaXNjaXBsaW5lcy4kW2Rpc2NpcGxpbmVdLmxhYnMuJFtsYWJdLnJhdGluZyc6IHJhdGluZyxcbiAgICAgICAgICAgICAgICAnZGlzY2lwbGluZXMuJFtkaXNjaXBsaW5lXS5sYWJzLiRbbGFiXS5tZXNzYWdlJzogbWVzc2FnZSxcbiAgICAgICAgICAgICAgICAnZGlzY2lwbGluZXMuJFtkaXNjaXBsaW5lXS5sYWJzLiRbbGFiXS5wb2ludHMnOiBwb2ludHMsXG4gICAgICAgICAgICB9LFxuICAgICAgICB9LCB7XG4gICAgICAgICAgICBhcnJheUZpbHRlcnM6IFtcbiAgICAgICAgICAgICAgICB7ICdkaXNjaXBsaW5lLnRlYWNoZXJFbWFpbCc6IHRlYWNoZXJFbWFpbCB9LFxuICAgICAgICAgICAgICAgIHsgJ2xhYi5uYW1lJzogbGFiTmFtZSB9LFxuICAgICAgICAgICAgXSxcbiAgICAgICAgICAgIG5ldzogdHJ1ZSxcbiAgICAgICAgfSk7XG4gICAgICAgIGNvbnN0IHJlc3BvbnNlID0gbmV3IEFwaVN1Y2Nlc3Moe1xuICAgICAgICAgICAgc3RhdHVzOiBTVEFUVVMuT0ssXG4gICAgICAgICAgICBtZXNzYWdlOiAnU3VjY2VzcycsXG4gICAgICAgICAgICBkYXRhOiB1cGRhdGVkU3R1ZGVudCxcbiAgICAgICAgfSk7XG4gICAgICAgIHJldHVybiByZXMuc3RhdHVzKHJlc3BvbnNlLnN0YXR1cykuc2VuZChyZXNwb25zZSk7XG4gICAgfVxuICAgIGNhdGNoIChlcnJvcikge1xuICAgICAgICBjb25zdCByZXNwb25zZSA9IEFwaUVycm9yLmludGVybmFsU2VydmVyRXJyb3IoZXJyb3IpO1xuICAgICAgICByZXR1cm4gcmVzLnN0YXR1cyhyZXNwb25zZS5zdGF0dXMpLnNlbmQocmVzcG9uc2UpO1xuICAgIH1cbiAgICBmaW5hbGx5IHtcbiAgICAgICAgcmVzLmVuZCgpO1xuICAgIH1cbn07XG4iLCJpbXBvcnQgeyBSb3V0ZXIgfSBmcm9tICdleHByZXNzJztcbmltcG9ydCB7IGdldCwgcHV0IH0gZnJvbSAnQC9hcGkvY29udHJvbGxlcnMvc3R1ZGVudCc7XG5jb25zdCBzdHVkZW50Um91dGVyID0gUm91dGVyKCk7XG5zdHVkZW50Um91dGVyLmdldCgnLycsIGdldCk7XG5zdHVkZW50Um91dGVyLnB1dCgnLycsIHB1dCk7XG5leHBvcnQgeyBzdHVkZW50Um91dGVyIH07XG4iLCJpbXBvcnQgeyBBcGlFcnJvciwgQXBpU3VjY2VzcywgU1RBVFVTIH0gZnJvbSAnQC9hcGkvcmVzcG9uc2VzJztcbmltcG9ydCB7IFVzZXJNb2RlbCB9IGZyb20gJ0AvRGF0YWJhc2UvbW9kZWxzL1VzZXInO1xuZXhwb3J0IGNvbnN0IGRlbCA9IGFzeW5jIChyZXEsIHJlcykgPT4ge1xuICAgIHRyeSB7XG4gICAgICAgIGNvbnN0IHsgZW1haWwgfSA9IHJlcS5ib2R5O1xuICAgICAgICBpZiAoZW1haWwgPT09IHVuZGVmaW5lZCkge1xuICAgICAgICAgICAgY29uc3QgcmVzcG9uc2UgPSBuZXcgQXBpRXJyb3Ioe1xuICAgICAgICAgICAgICAgIHN0YXR1czogU1RBVFVTLkJBRF9SRVFVRVNULFxuICAgICAgICAgICAgICAgIG1lc3NhZ2U6ICdNaXNzaW5nIHJlcXVpcmVkIGZpZWxkcycsXG4gICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIHJldHVybiByZXMuc3RhdHVzKHJlc3BvbnNlLnN0YXR1cykuc2VuZChyZXNwb25zZSk7XG4gICAgICAgIH1cbiAgICAgICAgY29uc3QgZm91bmQgPSBVc2VyTW9kZWwuZmluZE9uZSh7IGVtYWlsIH0pO1xuICAgICAgICBpZiAoZm91bmQgPT09IG51bGwgfHwgZm91bmQgPT09IHVuZGVmaW5lZCkge1xuICAgICAgICAgICAgY29uc3QgcmVzcG9uc2UgPSBuZXcgQXBpRXJyb3Ioe1xuICAgICAgICAgICAgICAgIHN0YXR1czogU1RBVFVTLkJBRF9SRVFVRVNULFxuICAgICAgICAgICAgICAgIG1lc3NhZ2U6ICdVc2VyIG5vdCBmb3VuZCcsXG4gICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIHJldHVybiByZXMuc3RhdHVzKHJlc3BvbnNlLnN0YXR1cykuc2VuZChyZXNwb25zZSk7XG4gICAgICAgIH1cbiAgICAgICAgYXdhaXQgVXNlck1vZGVsLmRlbGV0ZU9uZSh7IGVtYWlsIH0pO1xuICAgICAgICBjb25zdCByZXNwb25zZSA9IG5ldyBBcGlTdWNjZXNzKHtcbiAgICAgICAgICAgIHN0YXR1czogU1RBVFVTLk9LLFxuICAgICAgICAgICAgbWVzc2FnZTogJ1VzZXIgZGVsZXRlZCcsXG4gICAgICAgIH0pO1xuICAgICAgICByZXR1cm4gcmVzLnN0YXR1cyhyZXNwb25zZS5zdGF0dXMpLnNlbmQocmVzcG9uc2UpO1xuICAgIH1cbiAgICBjYXRjaCAoZXJyb3IpIHtcbiAgICAgICAgY29uc3QgcmVzcG9uc2UgPSBBcGlFcnJvci5pbnRlcm5hbFNlcnZlckVycm9yKGVycm9yKTtcbiAgICAgICAgcmV0dXJuIHJlcy5zdGF0dXMocmVzcG9uc2Uuc3RhdHVzKS5zZW5kKHJlc3BvbnNlKTtcbiAgICB9XG4gICAgZmluYWxseSB7XG4gICAgICAgIHJlcy5lbmQoKTtcbiAgICB9XG59O1xuIiwiaW1wb3J0IHsgQXBpRXJyb3IsIFNUQVRVUyB9IGZyb20gJ0AvYXBpL3Jlc3BvbnNlcyc7XG5pbXBvcnQgeyBVc2VyTW9kZWwgfSBmcm9tICdAL0RhdGFiYXNlL21vZGVscy9Vc2VyJztcbmV4cG9ydCBjb25zdCBwb3N0ID0gYXN5bmMgKHJlcSwgcmVzKSA9PiB7XG4gICAgdHJ5IHtcbiAgICAgICAgY29uc3QgeyBlbWFpbCwgcGFzc3dvcmQsIG5hbWUsIHVuaXZlcnNpdHlJZCwgc3BlY2lhbGl0eUlkLCBwZXJtcyB9ID0gcmVxLmJvZHk7XG4gICAgICAgIGlmIChlbWFpbCA9PT0gdW5kZWZpbmVkIHx8XG4gICAgICAgICAgICBwYXNzd29yZCA9PT0gdW5kZWZpbmVkIHx8XG4gICAgICAgICAgICBuYW1lID09PSB1bmRlZmluZWQgfHxcbiAgICAgICAgICAgIHVuaXZlcnNpdHlJZCA9PT0gdW5kZWZpbmVkIHx8XG4gICAgICAgICAgICBzcGVjaWFsaXR5SWQgPT09IHVuZGVmaW5lZCB8fFxuICAgICAgICAgICAgcGVybXMgPT09IHVuZGVmaW5lZCkge1xuICAgICAgICAgICAgY29uc3QgcmVzcG9uc2UgPSBuZXcgQXBpRXJyb3Ioe1xuICAgICAgICAgICAgICAgIHN0YXR1czogU1RBVFVTLkJBRF9SRVFVRVNULFxuICAgICAgICAgICAgICAgIG1lc3NhZ2U6ICdNaXNzaW5nIHJlcXVpcmVkIGZpZWxkcycsXG4gICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIHJldHVybiByZXMuc3RhdHVzKHJlc3BvbnNlLnN0YXR1cykuc2VuZChyZXNwb25zZSk7XG4gICAgICAgIH1cbiAgICAgICAgY29uc3QgdXNlciA9IGF3YWl0IFVzZXJNb2RlbC5jcmVhdGUoe1xuICAgICAgICAgICAgZW1haWwsXG4gICAgICAgICAgICBwYXNzd29yZCxcbiAgICAgICAgICAgIG5hbWUsXG4gICAgICAgICAgICBwZXJtcyxcbiAgICAgICAgICAgIHVuaXZlcnNpdHlfaWQ6IHVuaXZlcnNpdHlJZCxcbiAgICAgICAgICAgIHNwZWNpYWxpdHlfaWQ6IHNwZWNpYWxpdHlJZCxcbiAgICAgICAgfSk7XG4gICAgICAgIGNvbnN0IHZhbGlkYXRpb25FcnJvciA9IHVzZXIudmFsaWRhdGVTeW5jKCk7XG4gICAgICAgIGlmICh2YWxpZGF0aW9uRXJyb3IgIT09IHVuZGVmaW5lZCkge1xuICAgICAgICAgICAgY29uc3QgcmVzcG9uc2UgPSBuZXcgQXBpRXJyb3Ioe1xuICAgICAgICAgICAgICAgIHN0YXR1czogU1RBVFVTLkJBRF9SRVFVRVNULFxuICAgICAgICAgICAgICAgIG1lc3NhZ2U6ICdWYWxpZGF0aW9uIGVycm9yJyxcbiAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgcmV0dXJuIHJlcy5zdGF0dXMocmVzcG9uc2Uuc3RhdHVzKS5zZW5kKHJlc3BvbnNlKTtcbiAgICAgICAgfVxuICAgICAgICBhd2FpdCB1c2VyLnNhdmUoKTtcbiAgICAgICAgY29uc3QgcmVzcG9uc2UgPSB7XG4gICAgICAgICAgICBzdGF0dXM6IFNUQVRVUy5PSyxcbiAgICAgICAgICAgIG1lc3NhZ2U6ICdVc2VyIGNyZWF0ZWQnLFxuICAgICAgICAgICAgZGF0YTogdXNlcixcbiAgICAgICAgfTtcbiAgICAgICAgcmV0dXJuIHJlcy5zdGF0dXMocmVzcG9uc2Uuc3RhdHVzKS5zZW5kKHJlc3BvbnNlKTtcbiAgICB9XG4gICAgY2F0Y2ggKGVycm9yKSB7XG4gICAgICAgIGNvbnN0IHJlc3BvbnNlID0gQXBpRXJyb3IuaW50ZXJuYWxTZXJ2ZXJFcnJvcihlcnJvcik7XG4gICAgICAgIHJldHVybiByZXMuc3RhdHVzKHJlc3BvbnNlLnN0YXR1cykuc2VuZChyZXNwb25zZSk7XG4gICAgfVxuICAgIGZpbmFsbHkge1xuICAgICAgICByZXMuZW5kKCk7XG4gICAgfVxufTtcbiIsImltcG9ydCB7IFJvdXRlciB9IGZyb20gJ2V4cHJlc3MnO1xuaW1wb3J0IHsgZGVsLCBwb3N0IH0gZnJvbSAnQC9hcGkvY29udHJvbGxlcnMvYWRtaW4nO1xuY29uc3QgYWRtaW5Sb3V0ZXIgPSBSb3V0ZXIoKTtcbmFkbWluUm91dGVyLnBvc3QoJy91c2VyJywgcG9zdCk7XG5hZG1pblJvdXRlci5kZWxldGUoJy91c2VyJywgZGVsKTtcbmV4cG9ydCB7IGFkbWluUm91dGVyIH07XG4iLCJpbXBvcnQgeyBSb3V0ZXIgfSBmcm9tICdleHByZXNzJztcbmltcG9ydCB7IGxvZ2luUm91dGVyLCB1bml2ZXJzaXR5Um91dGVyIH0gZnJvbSAnLi9yb3V0ZXMnO1xuaW1wb3J0IHsgc3R1ZGVudFJvdXRlciB9IGZyb20gJ0AvYXBpL3JvdXRlcy9zdHVkZW50Um91dGVyJztcbmltcG9ydCB7IGFkbWluUm91dGVyIH0gZnJvbSAnLi9yb3V0ZXMvYWRtaW5Sb3V0ZXInO1xuY29uc3QgYXBpUm91dGVyID0gUm91dGVyKCk7XG5hcGlSb3V0ZXIudXNlKCcvdW5pdmVyc2l0eScsIHVuaXZlcnNpdHlSb3V0ZXIpO1xuYXBpUm91dGVyLnVzZSgnL2xvZ2luJywgbG9naW5Sb3V0ZXIpO1xuYXBpUm91dGVyLnVzZSgnL3N0dWRlbnQnLCBzdHVkZW50Um91dGVyKTtcbmFwaVJvdXRlci51c2UoJy9hZG1pbicsIGFkbWluUm91dGVyKTtcbmV4cG9ydCB7IGFwaVJvdXRlciB9O1xuIiwiaW1wb3J0IGJvZHlQYXJzZXIgZnJvbSAnYm9keS1wYXJzZXInO1xuaW1wb3J0IGNvbXByZXNzaW9uIGZyb20gJ2NvbXByZXNzaW9uJztcbmltcG9ydCBjb3JzIGZyb20gJ2NvcnMnO1xuaW1wb3J0IGV4cHJlc3MgZnJvbSAnZXhwcmVzcyc7XG5pbXBvcnQgaGVsbWV0IGZyb20gJ2hlbG1ldCc7XG5pbXBvcnQgeyBhcGlSb3V0ZXIgfSBmcm9tICdAL2FwaSc7XG5jb25zdCBzZXJ2ZXIgPSBleHByZXNzKCk7XG50cnkge1xuICAgIHNlcnZlci51c2UoYm9keVBhcnNlci51cmxlbmNvZGVkKHsgZXh0ZW5kZWQ6IHRydWUgfSkpO1xuICAgIHNlcnZlci51c2UoYm9keVBhcnNlci5qc29uKCkpO1xuICAgIHNlcnZlci51c2UoY29tcHJlc3Npb24oKSk7XG4gICAgc2VydmVyLnVzZShjb3JzKCkpO1xuICAgIHNlcnZlci51c2UoaGVsbWV0KHtcbiAgICAgICAgY29udGVudFNlY3VyaXR5UG9saWN5OiBmYWxzZSxcbiAgICB9KSk7XG4gICAgc2VydmVyLnVzZSgnL2FwaScsIGFwaVJvdXRlcik7XG4gICAgY29uc29sZS5sb2coJ1tTRVJWRVJdIEluaXRpYWxpemVkJyk7XG59XG5jYXRjaCAoZXJyb3IpIHtcbiAgICBjb25zb2xlLmVycm9yKGVycm9yKTtcbn1cbmV4cG9ydCB7IHNlcnZlciB9O1xuIiwiaW1wb3J0IHsgY29uZmlnIH0gZnJvbSAnZG90ZW52JztcbmNvbmZpZygpO1xuLy8gZ2xvYmFsXG5leHBvcnQgY29uc3QgUE9SVCA9IHByb2Nlc3MuZW52LlBPUlQgPz8gNDAwMDtcbi8vIGRhdGFiYXNlXG4vLyBkYXRhYmFzZVxuZXhwb3J0IGNvbnN0IERCX1VTRVIgPSBwcm9jZXNzLmVudi5EQl9VU0VSO1xuZXhwb3J0IGNvbnN0IERCX1BBU1MgPSBwcm9jZXNzLmVudi5EQl9QQVNTO1xuZXhwb3J0IGNvbnN0IERCX05BTUUgPSBwcm9jZXNzLmVudi5EQl9OQU1FO1xuZXhwb3J0IGNvbnN0IERCX0NPTk5TVFIgPSBwcm9jZXNzLmVudi5EQl9DT05OU1RSXG4gICAgLnJlcGxhY2UoJzx1c2VyPicsIERCX1VTRVIpXG4gICAgLnJlcGxhY2UoJzxwYXNzPicsIERCX1BBU1MpXG4gICAgLnJlcGxhY2UoJzxkYj4nLCBEQl9OQU1FKTtcbiIsImltcG9ydCB7IGNvbm5lY3QsIGNvbm5lY3Rpb24sIHNldCB9IGZyb20gJ21vbmdvb3NlJztcbmltcG9ydCB7IERCX0NPTk5TVFIsIERCX05BTUUgfSBmcm9tICdAL2NvbmZpZyc7XG5zZXQoJ3N0cmljdFF1ZXJ5JywgZmFsc2UpO1xuY2xhc3MgRGF0YWJhc2Uge1xuICAgIHN0YXRpYyBpbnN0YW5jZSA9IG51bGw7XG4gICAgY29uc3RydWN0b3IoKSB7XG4gICAgICAgIGlmIChEYXRhYmFzZS5pbnN0YW5jZSA9PT0gbnVsbClcbiAgICAgICAgICAgIERhdGFiYXNlLmluc3RhbmNlID0gdGhpcztcbiAgICAgICAgcmV0dXJuIERhdGFiYXNlLmluc3RhbmNlO1xuICAgIH1cbiAgICBpc0Nvbm5lY3RlZCA9ICgpID0+IGNvbm5lY3Rpb24ucmVhZHlTdGF0ZSA9PT0gMTtcbiAgICBjb25uZWN0ID0gYXN5bmMgKCkgPT4ge1xuICAgICAgICBjb25zdCBkZWZhdWx0UmV0dXJuID0gdGhpcy5pc0Nvbm5lY3RlZDtcbiAgICAgICAgaWYgKHRoaXMuaXNDb25uZWN0ZWQoKSlcbiAgICAgICAgICAgIHJldHVybiBkZWZhdWx0UmV0dXJuO1xuICAgICAgICBjb25zb2xlLmxvZygnW0RCXSBDb25uZWN0aW5nLi4uJyk7XG4gICAgICAgIHRyeSB7XG4gICAgICAgICAgICBhd2FpdCBjb25uZWN0KERCX0NPTk5TVFIpO1xuICAgICAgICAgICAgY29uc29sZS5sb2coYFtEQl0gQ29ubmVjdGVkIHRvIFwiJHtEQl9OQU1FfVwiYCk7XG4gICAgICAgIH1cbiAgICAgICAgY2F0Y2ggKGVycm9yKSB7XG4gICAgICAgICAgICBjb25zb2xlLmVycm9yKCdbREJdIENvbm5lY3Rpb24gZXJyb3InKTtcbiAgICAgICAgICAgIGNvbnNvbGUuZXJyb3IoZXJyb3IpO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiBkZWZhdWx0UmV0dXJuO1xuICAgIH07XG59XG5leHBvcnQgeyBEYXRhYmFzZSB9O1xuIiwiY29uc3QgbG9jYWxlID0gJ3VrLVVBJztcbmNvbnN0IHRpbWVab25lID0gJ0V1cm9wZS9LaWV2JztcbmV4cG9ydCBjb25zdCBnZXRDdXJyZW50VGltZVN0cmluZyA9ICgpID0+IG5ldyBEYXRlKCkudG9Mb2NhbGVUaW1lU3RyaW5nKGxvY2FsZSwge1xuICAgIHRpbWVab25lLFxuICAgIGhvdXI6ICcyLWRpZ2l0JyxcbiAgICBtaW51dGU6ICcyLWRpZ2l0JyxcbiAgICBzZWNvbmQ6ICcyLWRpZ2l0Jyxcbn0pO1xuZXhwb3J0IGNvbnN0IGdldEN1cnJlbnREYXRlU3RyaW5nID0gKCkgPT4gbmV3IERhdGUoKS50b0xvY2FsZURhdGVTdHJpbmcobG9jYWxlLCB7XG4gICAgdGltZVpvbmUsXG4gICAgd2Vla2RheTogJ2xvbmcnLFxuICAgIHllYXI6ICdudW1lcmljJyxcbiAgICBtb250aDogJ2xvbmcnLFxuICAgIGRheTogJ251bWVyaWMnLFxuICAgIGhvdXI6ICdudW1lcmljJyxcbiAgICBtaW51dGU6ICdudW1lcmljJyxcbn0pO1xuIiwiaW1wb3J0IHsgUE9SVCB9IGZyb20gJ0AvY29uZmlnJztcbmltcG9ydCB7IGdldEN1cnJlbnRUaW1lU3RyaW5nIH0gZnJvbSAnQC91dGlscyc7XG5leHBvcnQgY29uc3QgbWFpbkxpc3RlbiA9ICgpID0+IHtcbiAgICB0cnkge1xuICAgICAgICBjb25zb2xlLmxvZyhgW1NFUlZFUl0gfCAke2dldEN1cnJlbnRUaW1lU3RyaW5nKCl9IExpc3RlbmluZyBhdCAke1BPUlR9YCk7XG4gICAgfVxuICAgIGNhdGNoIChlcnJvcikge1xuICAgICAgICBjb25zb2xlLmVycm9yKGVycm9yKTtcbiAgICB9XG59O1xuIiwiaW1wb3J0IHsgc2VydmVyIH0gZnJvbSAnLi9zZXJ2ZXInO1xuaW1wb3J0IHsgRGF0YWJhc2UgfSBmcm9tICdAL0RhdGFiYXNlJztcbmltcG9ydCB7IG1haW5MaXN0ZW4gfSBmcm9tICdAL2FwaS9jb250cm9sbGVycy9tYWluJztcbmltcG9ydCB7IFBPUlQgfSBmcm9tICdAL2NvbmZpZyc7XG5jb25zdCBzdGFydCA9IGFzeW5jICgpID0+IHtcbiAgICBjb25zdCBkYXRhYmFzZSA9IG5ldyBEYXRhYmFzZSgpO1xuICAgIHZvaWQgc2VydmVyLmxpc3RlbihQT1JULCBtYWluTGlzdGVuKTtcbiAgICB2b2lkIGRhdGFiYXNlLmNvbm5lY3QoKTtcbn07XG52b2lkIHN0YXJ0KCk7XG4iXSwibmFtZXMiOlsiU1RBVFVTLklOVEVSTkFMX1NFUlZFUl9FUlJPUiIsIkVSUk9SLklOVEVSTkFMX1NFUlZFUiIsIlNjaGVtYSIsIm1vZGVscyIsIm1vZGVsIiwicG9zdCIsIlNUQVRVUy5CQURfUkVRVUVTVCIsIlNUQVRVUy5VTkFVVEhPUklaRUQiLCJTVEFUVVMuT0siLCJSb3V0ZXIiLCJnZXQiLCJjb25maWciLCJzZXQiLCJjb25uZWN0aW9uIiwiY29ubmVjdCJdLCJtYXBwaW5ncyI6Ijs7Ozs7Ozs7O0FBQUEsTUFBTSw0QkFBNEIsR0FBRyxNQUFNLENBQUMsOEJBQThCLEVBQUM7QUFDM0UsTUFBTSxrQkFBa0IsR0FBRztBQUMzQixDQUFDLGFBQWEsRUFBRSxDQUFDLFFBQVEsQ0FBQztBQUMxQixDQUFDLFVBQVUsRUFBRSxDQUFDLFFBQVEsQ0FBQztBQUN2QixDQUFDLFVBQVUsRUFBRSxDQUFDLFFBQVEsRUFBRSxRQUFRLEVBQUUsT0FBTyxDQUFDO0FBQzFDLENBQUMsYUFBYSxFQUFFLENBQUMsUUFBUSxDQUFDO0FBQzFCLENBQUMsaUJBQWlCLEVBQUUsQ0FBQyxRQUFRLENBQUM7QUFDOUIsQ0FBQyxTQUFTLEVBQUUsQ0FBQyxRQUFRLEVBQUUsT0FBTyxDQUFDO0FBQy9CLENBQUMsWUFBWSxFQUFFLENBQUMsUUFBUSxDQUFDO0FBQ3pCLENBQUMsWUFBWSxFQUFFLENB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
