const AWS = require('aws-sdk');
const https = require('https');
const queryString = require('querystring');
const msal = require("msal");

/**
 * @param {object} event            event passed from sftp server
 * @param {string} event.username   username of sftp user
 * @param {string} event.password   password of sftp user
 * @returns                         access response
 */

exports.handler = async (event) => {
    // Get the tenantId, clientId, redirectUri, bucket, s3Role from the event
    const { tenantId, clientId, bucket, s3Role } = event;

    const config = {
        auth: {
            clientId,
            authority: `https://login.microsoftonline.com/${tenantId}`
        }
    };
    const userAgentApplication = new msal.UserAgentApplication(config);

    // Get the username and password from the event
    const { userName, password } = event;
    const domain = tenantId;

    if (userName.includes('%40')) {
        userName = decodeURIComponent(userName);
    } else {
        userName = `${userName}@${domain}`;
    };

    try {
        // Log in the user and wait for the MFA response
        const loginResponse = await userAgentApplication.loginPopup({
            userName,
            password
        });

        if (loginResponse.account) {
            // The user has successfully authenticated
            // You can now use the access token to make API calls
            const accessToken = await userAgentApplication.acquireTokenSilent({
                account: loginResponse.account,
                scopes: ["https://graph.microsoft.com/User.Read"]
            });
            var response = {
                Role: s3Role,
                HomeBucket: bucket,
                HomeDirectory: '/' + bucket + '/' + userName.split("@")[0].toLowerCase(),
                Policy: JSON.stringify(scopedPolicy)
            };
            console.log({ status: 'Success', user: userName, scope: token.scope });
            return {
                statusCode: 200,
                body: JSON.stringify({ response, accessToken })
            };
        } else {
            // The user did not successfully authenticate
            console.log({ status: 'Failure', user: userName, error: token.error, errorUri: token.error_uri });
            return {
                statusCode: 401,
                body: JSON.stringify({ error: "Unauthorized" })
            };
        }
    } catch (err) {
        return {
            statusCode: 500,
            body: JSON.stringify({ error: err.message })
        };
    }
}


/**
 * @param {object} options          https options
 * @param {string} options.host     https domain or root url
 * @param {string} options.path     https url endpoint to hit
 * @param {string} options.port     https port to use - defaults to 443
 * @param {string} options.method   https method POST | GET | PUT | DELETE
 * @param {object} options.headers  Header data that needs to be passed the call
 * @param {object} postData         data that should be sent in a post body
 * @returns 
 */
var webRequest = (options, postData) => new Promise((resolve) => {
    const req = https.request(options, res => {
        var chunk = '';
        res.on('data', d => {
            chunk += d
        }).on('end', () => {
            var response = JSON.parse(chunk.toString());
            response.statusCode = res.statusCode;
            resolve(response);
        });
    });
    req.on('error', error => {
        console.error('error', error);
    });
    if (postData) { req.write(postData); };
    req.end();
});

/**
 * @param {string} variable         environment variable encrypted by KMS
 * @returns                         decrypted variable 
 */
var decryptVariable = (variable) => new Promise((resolve) => {
    if (!variable.startsWith('AQICA')) { return resolve(variable) };
    var aws = new AWS.KMS().decrypt({
        CiphertextBlob: Buffer.from(variable, 'base64'),
        EncryptionContext: { LambdaFunctionName: process.env.AWS_LAMBDA_FUNCTION_NAME }
    });
    aws.on('success', r => {
        resolve(r.data.Plaintext.toString('ascii'));
    }).on('error', e => {
        console.log('error decrypting key', e.message);
    }).send();
});

// this is our scoped policy that will determine the access rights of the user
var scopedPolicy = {
    Version: '2012-10-17',
    Statement: [
        {
            Sid: 'allowFolderList',
            Action: [
                's3:ListBucket'
            ],
            Effect: 'Allow',
            Resource: [
                'arn:aws:s3:::${transfer:HomeBucket}'
            ],
            Condition: {
                StringLike: {
                    's3:prefix': [
                        '${transfer:UserName}/*'
                    ]
                }
            }
        },
        {
            Sid: 'HomeDirectoryAccess',
            Effect: 'Allow',
            Action: [
                's3:GetObject',
                's3:GetObjectVersion'
            ],
            Resource: [
                'arn:aws:s3:::${transfer:HomeDirectory}/*'
            ]
        },
        {
            Sid: 'DenyDeletionOfHomeDirectory',
            Effect: 'Deny',
            Action: [
                's3:DeleteObjectVersion',
                's3:DeleteObject'
            ],
            Resource: [
                'arn:aws:s3:::${transfer:HomeDirectory}/'
            ]
        }
    ]
};