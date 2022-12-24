const AWS = require('aws-sdk');
const https = require('https');
const queryString = require('querystring');

/**
 * @param {object} event            event passed from sftp server
 * @param {string} event.username   username of sftp user
 * @param {string} event.password   password of sftp user
 * @returns                         access response
 */
exports.handler = async (event) => {
    const tenantId = await decryptVariable(process.env.TenantID);
    const clientId = await decryptVariable(process.env.AzureClientId);
    const bucket = await decryptVariable(process.env.S3BucketName);
    const s3Role = await decryptVariable(process.env.S3RoleArn);

    //if using tenantId (the guid id) set this to your domain name example: mydomain.com
    const domain = tenantId;

    var userName = event.username;

    if (userName.includes('%40')) {
        userName = decodeURIComponent(userName);
    } else {
        userName = `${userName}@${domain}`;
    };

    var credentials = {
        client_id: clientId,
        response_type: 'token',
        scope: 'https://graph.microsoft.com/User.Read',
        grant_type: 'password',
        username: userName,
        password: event.password
    };

    var postData = queryString.stringify(credentials);
    var options = {
        method: 'POST',
        host: 'login.microsoftonline.com',
        path: `/${tenantId}/oauth2/v2.0/token`,
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': postData.length
        }
    };

    var token = await webRequest(options, postData);

    if (!token.access_token) {
        if (token.error) {
            console.log({ status: 'Failure', user: userName, error: token.error, errorUri: token.error_uri });
        };
        return {};
    } else {
        console.log({ status: 'Success', user: userName, scope: token.scope });

        /**
         * Add Additional login here!
         */
        var response = {
            Role: s3Role,
            HomeBucket: bucket,
            HomeDirectory: '/' + bucket + '/' + userName.split("@")[0].toLowerCase(),
            Policy: JSON.stringify(scopedPolicy)
        };
        return response;
    };
};

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