const { attachRequestContext, errorHandler } = require('../../src/middleware/security');

describe('Security middleware', () => {
  const originalNodeEnv = process.env.NODE_ENV;
  const originalRailwayEnv = process.env.RAILWAY_ENVIRONMENT_NAME;

  afterEach(() => {
    process.env.NODE_ENV = originalNodeEnv;
    process.env.RAILWAY_ENVIRONMENT_NAME = originalRailwayEnv;
  });

  it('attachRequestContext should preserve incoming x-request-id', () => {
    const req = {
      headers: { 'x-request-id': 'req-123' }
    };

    const res = {
      setHeader: jest.fn()
    };

    const next = jest.fn();

    attachRequestContext(req, res, next);

    expect(req.requestId).toBe('req-123');
    expect(res.setHeader).toHaveBeenCalledWith('X-Request-Id', 'req-123');
    expect(next).toHaveBeenCalled();
  });

  it('errorHandler should hide internal error messages in production for 500 responses', () => {
    process.env.NODE_ENV = 'production';
    process.env.RAILWAY_ENVIRONMENT_NAME = 'production';

    const req = {
      requestId: 'req-prod-500',
      method: 'GET',
      originalUrl: '/api/test'
    };

    const json = jest.fn();
    const res = {
      status: jest.fn(() => ({ json }))
    };

    const err = new Error('Database connection failed with credentials');
    err.status = 500;

    errorHandler(err, req, res, jest.fn());

    expect(res.status).toHaveBeenCalledWith(500);
    expect(json).toHaveBeenCalledWith({
      success: false,
      error: 'Internal server error',
      requestId: 'req-prod-500'
    });
  });

  it('errorHandler should keep explicit client-safe errors for 4xx responses', () => {
    process.env.NODE_ENV = 'production';
    process.env.RAILWAY_ENVIRONMENT_NAME = 'production';

    const req = {
      requestId: 'req-prod-400',
      method: 'POST',
      originalUrl: '/api/test'
    };

    const json = jest.fn();
    const res = {
      status: jest.fn(() => ({ json }))
    };

    const err = new Error('Invalid payload');
    err.status = 400;

    errorHandler(err, req, res, jest.fn());

    expect(res.status).toHaveBeenCalledWith(400);
    expect(json).toHaveBeenCalledWith({
      success: false,
      error: 'Invalid payload',
      requestId: 'req-prod-400'
    });
  });
});
