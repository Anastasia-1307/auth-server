import { RateLimiterMemory } from 'rate-limiter-flexible';
import { Elysia } from 'elysia';

// Rate limiter configurations
const authLimiter = new RateLimiterMemory({
  keyPrefix: 'auth_limit',
  points: 5, // Number of requests
  duration: 900, // Per 15 minutes
  blockDuration: 900, // Block for 15 minutes
});

const tokenLimiter = new RateLimiterMemory({
  keyPrefix: 'token_limit',
  points: 20, // Number of requests
  duration: 300, // Per 5 minutes
  blockDuration: 300, // Block for 5 minutes
});

const generalLimiter = new RateLimiterMemory({
  keyPrefix: 'general_limit',
  points: 100, // Number of requests
  duration: 60, // Per 1 minute
  blockDuration: 60, // Block for 1 minute
});

export const rateLimitPlugin = (app: Elysia) => {
  return app
    .onRequest(async ({ request, set }) => {
      const ip = request.headers.get('x-forwarded-for') || 
                request.headers.get('x-real-ip') || 
                'unknown';
      
      const path = new URL(request.url).pathname;
      
      try {
        // Different limits for different endpoints
        if (path.startsWith('/login')) {
          await authLimiter.consume(ip);
        } else if (path.startsWith('/token') || path.startsWith('/oauth')) {
          await tokenLimiter.consume(ip);
        } else {
          await generalLimiter.consume(ip);
        }
      } catch (rejRes: any) {
        const secs = Math.round(rejRes.msBeforeNext / 1000) || 1;
        set.status = 429;
        set.headers['Retry-After'] = String(secs);
        throw new Error(`Too many requests. Try again in ${secs} seconds.`);
      }
    });
};

export { authLimiter, tokenLimiter, generalLimiter };
