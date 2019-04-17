require('dotenv').config({ silent: true });
const _ = require('underscore');

// Load swagger documentation
var fs = require('fs');
var swagger = JSON.parse(fs.readFileSync('swagger.json', 'utf8'));

const jwksClient = require('jwks-rsa');
const jwt = require('jsonwebtoken');
const util = require('util');

const getPolicyDocument = (effect, resource) => {
    const policyDocument = {
        Version: '2012-10-17', // default version
        Statement: [{
            Action: 'execute-api:Invoke', // default action
            Effect: effect,
            Resource: resource,
        }]
    };
    return policyDocument;
}


// extract and return the Bearer Token from the Lambda event parameters
const getToken = (params) => {

    const tokenString = params.headers["Authorization"];
    if (!tokenString) {
        throw new Error('Expected "event.authorizationToken" parameter to be set');
    }

    const match = tokenString.match(/^Bearer (.*)$/);
    if (!match || match.length < 2) {
        throw new Error(`Invalid Authorization token - ${tokenString} does not match "Bearer .*"`);
    }
    return match[1];
}

const getPath = (params) => {
    return params.requestContext.resourcePath;
}

const permittedScopesForPath = (path) => {
    const paths = swagger["paths"];
    const matchedPath = paths[path];
    if (!matchedPath) {
        throw new Error("No matching resource path documented.")
    }
    const permitted = matchedPath["x-permitted-scopes"];
    if (!permitted) {
        throw new Error("No matching scopes for resource path.")
    }
    return _.flatten([permitted.split(" ")]);
}


const containsScopes = (inbound, permitted) => {
    return _.intersection(inbound, permitted).length > 0;
}

const scopesFromToken = (decoded) => {
    return _.flatten([decoded.payload.scope.split(" ")]);
}

const jwtOptions = {
    audience: process.env.AUDIENCE,
    issuer: process.env.TOKEN_ISSUER
};

module.exports.authenticate = (params) => {
    const token = getToken(params);
    const path = getPath(params)
    const permittedScopes = permittedScopesForPath(path);

    const decoded = jwt.decode(token, { complete: true });
    if (!decoded || !decoded.header || !decoded.header.kid) {
        throw new Error('invalid token');
    }

    const jwtScopes = scopesFromToken(decoded);

    // check scopes
    if (!containsScopes(jwtScopes, permittedScopes)) {
        throw new Error('invalid access');
    }

    const client = jwksClient({
        cache: true,
        rateLimit: true,
        jwksRequestsPerMinute: 10, // Default value
        jwksUri: process.env.JWKS_URI
    });

    const getSigningKey = util.promisify(client.getSigningKey);
    return getSigningKey(decoded.header.kid)
        .then((key) => {
            const signingKey = key.publicKey || key.rsaPublicKey;
            return jwt.verify(token, signingKey, jwtOptions);
        })
        .then((decoded)=> ({
            principalId: decoded.sub,
            policyDocument: getPolicyDocument('Allow', params.methodArn),
            context: { scope: decoded.scope }
        }));
}
