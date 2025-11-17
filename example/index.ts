import { getOAuthProtectedResourceMetadataUrl, mcpAuthRouter } from '@modelcontextprotocol/sdk/server/auth/router.js';
import express from 'express';
import { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { OAuthServer } from '../src/OAuthServer.js';
import { authenticateHandler } from '../src/handlers/authenticate.js';
import { MemoryOAuthServerModel } from '../src/MemoryOAuthServerModel.js';

const memoryOAuthServerModel = new MemoryOAuthServerModel();

const mcpServerUrl = new URL('http://localhost:3000/mcp');

const mcpOAuthProvider = new OAuthServer({
    model: memoryOAuthServerModel,
    authorizationUrl: new URL('http://localhost:3000/consent'),
    mcpServerUrl,
    scopesSupported: ['mcp:tools'],
    modifyAuthorizationRedirectUrl: (url, client, params) => {
        // Include metadata in the query string we can display on the consent screen.
        // The site holding the consent screen could also query the backend for this data
        // because the client_id is set in the query string.
        if (client.client_name) url.searchParams.set('client_name', client.client_name);
        if (client.client_uri) url.searchParams.set('client_uri', client.client_uri);
        if (client.logo_uri) url.searchParams.set('logo_uri', client.logo_uri);
    },
});

const mcpAuthMiddleware = mcpAuthRouter({
    provider: mcpOAuthProvider,
    issuerUrl: new URL('http://localhost:3000/'),
    resourceServerUrl: mcpServerUrl,
    scopesSupported: ['mcp:tools'],

    clientRegistrationOptions: {
        clientIdGeneration: true,
    },
});

function main() {
    const app = express();

    app.use(express.json());
    app.use(express.urlencoded({ extended: true }));

    app.use((req, res, next) => {
        res.on('finish', () => {
            console.log('--------------------------------');
            console.log(req.method, req.originalUrl, res.statusCode);
        });

        // res.on('finish', () => {
        //     console.log('\n', req.method, req.originalUrl, res.statusCode, '\n');
        // });
        next();
    });

    // You currently cannot run the authorization endpoint on a path other than root /
    // https://github.com/modelcontextprotocol/typescript-sdk/pull/1095
    app.use(mcpAuthMiddleware);

    // the /authorize request handled by mcpAuthMiddleware will redirect to the /consent page
    app.get('/consent', (req, res) => {
        const qs = new URLSearchParams(req.query as Record<string, string>);

        const clientName = qs.get('client_name');
        const resource = qs.get('resource');

        res.setHeader('Content-Type', 'text/html');
        res.send(`
            <html>
                <body>
                    <h1>Login to ${clientName || resource}</h1>
                    <form action="/confirm?${qs.toString()}" method="POST">
                        <input type="text" name="user_id" placeholder="User ID to authenticate as" required>
                        <input type="submit" value="Give consent">
                    </form>
                    <pre>${JSON.stringify(Object.fromEntries(qs.entries()), null, 2)}</pre>
                </body>
            </html>
        `);
    });

    app.use(
        '/confirm',
        authenticateHandler({
            provider: mcpOAuthProvider,
            getUser: async (req) => {
                const userId = req.body.user_id;
                return userId;
            },
        }),
    );
    // You can run the MCP server on another server as long as mcpOAuthProvider and
    app.post(
        '/mcp',
        requireBearerAuth({
            verifier: mcpOAuthProvider,
            requiredScopes: ['mcp:tools'],
            resourceMetadataUrl: getOAuthProtectedResourceMetadataUrl(mcpServerUrl),
        }),
    );

    app.post('/mcp', async (req, res) => {
        const userId = req.auth!.token;
        console.log('MCP request received from token:', userId);

        const transport = new StreamableHTTPServerTransport({
            sessionIdGenerator: undefined,
            enableJsonResponse: true,
        });

        res.on('close', () => {
            transport.close();
        });

        // Create an MCP server
        const mcpServer = new McpServer({
            name: 'demo-server',
            version: '1.0.0',
        });

        // Add an addition tool
        mcpServer.registerTool(
            'whoami',
            {
                title: 'Who Am I Tool',
                description: 'Returns the current user id',
            },
            () => {
                return {
                    content: [{ type: 'text' as const, text: userId }],
                    structuredContent: { result: userId },
                };
            },
        );

        await mcpServer.connect(transport);
        await transport.handleRequest(req, res, req.body);
    });

    app.listen(3000, () => {
        console.log('Server is running on port 3000');
    });
}

main();
