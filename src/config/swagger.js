const swaggerJsdoc = require('swagger-jsdoc');

const options = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'Asset Management System API',
      version: '1.0.0',
      description: 'QR-based Asset Management System for tracking keys, laptops, monitors, accessories, and ID cards',
      contact: {
        name: 'API Support',
        email: 'support@assetmanagement.com'
      },
      license: {
        name: 'ISC',
        url: 'https://opensource.org/licenses/ISC'
      }
    },
    servers: [
      {
        url: 'http://localhost:5000',
        description: 'Development server'
      },
      {
        url: 'https://api.assetmanagement.com',
        description: 'Production server'
      }
    ],
    components: {
      securitySchemes: {
        sessionAuth: {
          type: 'apiKey',
          in: 'cookie',
          name: 'connect.sid',
          description: 'Session-based authentication using express-session'
        },
        csrfToken: {
          type: 'apiKey',
          in: 'header',
          name: 'CSRF-Token',
          description: 'CSRF token required for POST/PUT/DELETE operations'
        }
      },
      schemas: {
        User: {
          type: 'object',
          required: ['username', 'email', 'password'],
          properties: {
            id: { type: 'integer', readOnly: true },
            username: { type: 'string', minLength: 3, maxLength: 100 },
            email: { type: 'string', format: 'email' },
            password: { type: 'string', minLength: 8, writeOnly: true },
            role: { type: 'string', enum: ['user', 'admin'], default: 'user' },
            department: { type: 'string', maxLength: 100 },
            oauth_provider: { type: 'string', enum: ['google', 'microsoft', 'github'] },
            created_at: { type: 'string', format: 'date-time', readOnly: true },
            updated_at: { type: 'string', format: 'date-time', readOnly: true }
          }
        },
        Key: {
          type: 'object',
          required: ['case_name', 'key_reference', 'location', 'employee_name', 'collection_date'],
          properties: {
            id: { type: 'integer', readOnly: true },
            case_name: { type: 'string', description: 'Case/Project name' },
            key_reference: { type: 'string', description: 'Key identifier' },
            location: { 
              type: 'string',
              enum: ['EJARI', 'RDC', 'RDC General Services', 'RERA', 'Rera General Services', 'RDC Electrical Enforcement']
            },
            employee_name: { type: 'string' },
            collection_date: { type: 'string', format: 'date' },
            remarks: { type: 'string' },
            created_at: { type: 'string', format: 'date-time', readOnly: true },
            updated_at: { type: 'string', format: 'date-time', readOnly: true }
          }
        },
        Laptop: {
          type: 'object',
          required: ['asset_name', 'asset_tag', 'location', 'employee_name', 'collection_date'],
          properties: {
            id: { type: 'integer', readOnly: true },
            asset_name: { type: 'string', description: 'Laptop model/name' },
            asset_tag: { type: 'string', description: 'Unique asset tag' },
            location: { type: 'string' },
            employee_name: { type: 'string' },
            collection_date: { type: 'string', format: 'date' },
            remarks: { type: 'string' },
            created_at: { type: 'string', format: 'date-time', readOnly: true }
          }
        },
        Monitor: {
          type: 'object',
          required: ['asset_name', 'asset_tag', 'location', 'employee_name', 'collection_date'],
          properties: {
            id: { type: 'integer', readOnly: true },
            asset_name: { type: 'string' },
            asset_tag: { type: 'string', description: 'Unique asset tag' },
            location: { type: 'string' },
            employee_name: { type: 'string' },
            collection_date: { type: 'string', format: 'date' },
            remarks: { type: 'string' }
          }
        },
        Accessory: {
          type: 'object',
          required: ['asset_name', 'location', 'employee_name', 'collection_date'],
          properties: {
            id: { type: 'integer', readOnly: true },
            asset_name: { type: 'string' },
            asset_tag: { type: 'string' },
            location: { type: 'string' },
            employee_name: { type: 'string' },
            collection_date: { type: 'string', format: 'date' },
            remarks: { type: 'string' }
          }
        },
        IDCard: {
          type: 'object',
          required: ['asset_name', 'employee_id', 'location', 'employee_name', 'collection_date'],
          properties: {
            id: { type: 'integer', readOnly: true },
            asset_name: { type: 'string', description: 'ID card type' },
            employee_id: { type: 'string', description: 'Employee ID number' },
            location: { type: 'string' },
            employee_name: { type: 'string' },
            collection_date: { type: 'string', format: 'date' },
            remarks: { type: 'string' }
          }
        },
        Error: {
          type: 'object',
          properties: {
            success: { type: 'boolean', default: false },
            error: { type: 'string' },
            message: { type: 'string' }
          }
        }
      },
      responses: {
        UnauthorizedError: {
          description: 'Authentication required',
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/Error' },
              example: { success: false, error: 'Unauthorized' }
            }
          }
        },
        ForbiddenError: {
          description: 'CSRF token missing or invalid',
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/Error' },
              example: { success: false, error: 'Invalid CSRF token' }
            }
          }
        }
      }
    },
    tags: [
      { name: 'Authentication', description: 'User authentication and authorization' },
      { name: 'Assets', description: 'Asset CRUD operations for all categories' },
      { name: 'Health', description: 'System health and status checks' }
    ]
  },
  apis: [
    './src/routes/*.js',
    './src/controllers/*.js'
  ]
};

const swaggerSpec = swaggerJsdoc(options);

module.exports = swaggerSpec;
