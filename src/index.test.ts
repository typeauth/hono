import { typeauthMiddleware, TypeauthConfig, TypeauthResponse } from './index';
import { Hono, Context } from 'hono';
import { HTTPException } from 'hono/http-exception';

// Mock the `fetch` function
global.fetch = jest.fn();

describe('typeauthMiddleware', () => {
  let app: Hono;
  const mockAppId = 'mock-app-id';

  beforeEach(() => {
    app = new Hono();
    (fetch as jest.Mock).mockClear();
  });

  it('should authenticate successfully with valid token', async () => {
    const mockToken = 'valid-token';
    const mockResponse: TypeauthResponse<boolean> = { result: true };

    (fetch as jest.Mock).mockResolvedValueOnce({
      ok: true,
      json: jest.fn().mockResolvedValueOnce({ success: true, valid: true }),
    });

    app.use(typeauthMiddleware({ appId: mockAppId }));
    app.get('/', (c) => c.text('Authenticated'));

    const req = new Request('http://localhost/', {
      headers: { Authorization: `Bearer ${mockToken}` },
    });
    const res = await app.request(req);

    expect(res.status).toBe(200);
    expect(await res.text()).toBe('Authenticated');
    expect(fetch).toHaveBeenCalledWith(
      'https://api.typeauth.com/authenticate',
      expect.objectContaining({
        method: 'POST',
        body: expect.stringContaining(`"token":"${mockToken}"`),
      })
    );
  });

  it('should return 401 error for missing token', async () => {
    app.use(typeauthMiddleware({ appId: mockAppId }));

    const req = new Request('http://localhost/');
    const res = await app.request(req);

    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: 'Missing token' });
  });

  it('should return 401 error for invalid token', async () => {
    const mockToken = 'invalid-token';
    const mockError = {
      message: 'Typeauth authentication failed',
      docs: 'https://docs.typeauth.com/errors/authentication',
    };

    (fetch as jest.Mock).mockResolvedValueOnce({
      ok: true,
      json: jest.fn().mockResolvedValueOnce({ success: false, valid: false }),
    });

    app.use(typeauthMiddleware({ appId: mockAppId }));

    const req = new Request('http://localhost/', {
      headers: { Authorization: `Bearer ${mockToken}` },
    });
    const res = await app.request(req);

    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: mockError.message });
  });

  it('should retry authentication on API failure', async () => {
    const mockToken = 'valid-token';
    const mockResponse: TypeauthResponse<boolean> = { result: true };

    (fetch as jest.Mock)
      .mockRejectedValueOnce(new Error('API error'))
      .mockResolvedValueOnce({
        ok: true,
        json: jest.fn().mockResolvedValueOnce({ success: true, valid: true }),
      });

    app.use(typeauthMiddleware({ appId: mockAppId, maxRetries: 2, retryDelay: 10 }));
    app.get('/', (c) => c.text('Authenticated'));

    const req = new Request('http://localhost/', {
      headers: { Authorization: `Bearer ${mockToken}` },
    });
    const res = await app.request(req);

    expect(res.status).toBe(200);
    expect(await res.text()).toBe('Authenticated');
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  // Add more test cases as needed
});