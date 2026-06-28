import { signJwt } from '../utils/jwt';
import { createResponse } from '../utils/response';
import { hashPassword, verifyPassword, isValidEmail, isValidUsername, isValidPassword } from '../utils/password';
import type { Env } from '../index';

/**
 * 账号认证控制器（支持账号密码注册和登录）
 *
 * 流程:
 *  1. POST /api/auth/register       → 验证 → 创建账号 → JWT → Set-Cookie
 *  2. POST /api/auth/login/account  → 验证密码 → JWT → Set-Cookie
 *  3. GET  /api/auth/logout         → 清除 Cookie
 */
export class AccountAuthController {

    private static log(stage: string, message: string, data?: any): void {
        const ts = new Date().toISOString();
        const detail = data !== undefined ? ` | ${JSON.stringify(data)}` : '';
        console.log(`[AccountAuth][${stage}] ${ts} ${message}${detail}`);
    }

    private static getCorsOrigin(request: Request, env: Env): string | null {
        if (env.CORS_ALLOW_ORIGIN && env.CORS_ALLOW_ORIGIN !== '*') {
            return env.CORS_ALLOW_ORIGIN;
        }
        if (env.FRONTEND_URL) {
            try {
                return new URL(env.FRONTEND_URL).origin;
            } catch {
                return request.headers.get('Origin');
            }
        }
        return request.headers.get('Origin');
    }

    private static withCors(response: Response, request: Request, env: Env): Response {
        const origin = AccountAuthController.getCorsOrigin(request, env);
        if (!origin) {
            return response;
        }
        const headers = new Headers(response.headers);
        headers.set('Access-Control-Allow-Origin', origin);
        headers.set('Access-Control-Allow-Credentials', 'true');
        headers.set('Vary', 'Origin');
        return new Response(response.body, { status: response.status, headers });
    }

    /* ──────────── 1. 用户注册 ──────────── */

    static async register(request: Request, env: Env): Promise<Response> {
        AccountAuthController.log('register', '收到注册请求');

        if (request.method !== 'POST') {
            return AccountAuthController.withCors(
                createResponse(405, 'Method Not Allowed'),
                request,
                env
            );
        }

        try {
            let body: any;
            try {
                body = await request.json();
            } catch {
                return AccountAuthController.withCors(
                    createResponse(400, '请求体必须是有效的 JSON'),
                    request,
                    env
                );
            }

            const { username, email, password } = body;

            // 参数校验
            if (!username || !email || !password) {
                AccountAuthController.log('register', '❌ 缺少必要参数', { username: !!username, email: !!email, password: !!password });
                return AccountAuthController.withCors(
                    createResponse(400, '缺少必要参数: username, email, password'),
                    request,
                    env
                );
            }

            // 验证用户名格式
            if (!isValidUsername(username)) {
                AccountAuthController.log('register', '❌ 用户名格式无效', { username });
                return AccountAuthController.withCors(
                    createResponse(400, '用户名格式无效，需要 3-32 个字符（字母、数字、下划线、连字符）'),
                    request,
                    env
                );
            }

            // 验证邮箱格式
            if (!isValidEmail(email)) {
                AccountAuthController.log('register', '❌ 邮箱格式无效', { email });
                return AccountAuthController.withCors(
                    createResponse(400, '邮箱格式无效'),
                    request,
                    env
                );
            }

            // 验证密码强度
            if (!isValidPassword(password)) {
                AccountAuthController.log('register', '❌ 密码强度不足');
                return AccountAuthController.withCors(
                    createResponse(400, '密码过弱，需要至少 8 个字符，包含字母和数字'),
                    request,
                    env
                );
            }

            // 检查用户名是否已存在
            AccountAuthController.log('register', '检查用户名是否存在', { username });
            const existingByUsername = await env.DB
                .prepare('SELECT user_id FROM users WHERE username = ?1')
                .bind(username)
                .first();

            if (existingByUsername) {
                AccountAuthController.log('register', '❌ 用户名已存在', { username });
                return AccountAuthController.withCors(
                    createResponse(409, '用户名已存在'),
                    request,
                    env
                );
            }

            // 检查邮箱是否已存在
            AccountAuthController.log('register', '检查邮箱是否存在', { email });
            const existingByEmail = await env.DB
                .prepare('SELECT user_id FROM users WHERE email = ?1')
                .bind(email)
                .first();

            if (existingByEmail) {
                AccountAuthController.log('register', '❌ 邮箱已存在', { email });
                return AccountAuthController.withCors(
                    createResponse(409, '邮箱已被注册'),
                    request,
                    env
                );
            }

            // 对密码进行哈希处理
            AccountAuthController.log('register', '对密码进行哈希处理');
            const passwordHash = await hashPassword(password);

            // 生成 user_id
            const userId = crypto.randomUUID();

            // 创建用户
            AccountAuthController.log('register', '创建用户', { userId, username, email });
            await env.DB
                .prepare(
                    `INSERT INTO users (user_id, username, email, password_hash, nickname, auth_type, created_at, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, 'account', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`
                )
                .bind(userId, username, email, passwordHash, username)
                .run();

            AccountAuthController.log('register', '✅ 用户创建成功', { userId });

            // 签发 JWT
            const now = Math.floor(Date.now() / 1000);
            const exp = now + 7 * 24 * 3600;
            AccountAuthController.log('register', '签发 JWT', { userId, iat: now, exp });
            const jwt = await signJwt(
                { userId, username, iat: now, exp },
                env.JWT_SECRET,
            );

            // Set-Cookie
            const cookieParts = [
                `token=${jwt}`,
                'Path=/',
                'HttpOnly',
                'Secure',
                'SameSite=Lax',
                `Max-Age=${7 * 24 * 3600}`,
            ];
            if (env.COOKIE_DOMAIN) {
                cookieParts.push(`Domain=${env.COOKIE_DOMAIN}`);
            }
            const cookie = cookieParts.join('; ');

            const resp = createResponse(200, 'success', {
                user_id: userId,
                username,
                email,
                message: '注册成功',
            });
            const headers = new Headers(resp.headers);
            headers.append('Set-Cookie', cookie);

            return AccountAuthController.withCors(
                new Response(resp.body, { status: resp.status, headers }),
                request,
                env
            );
        } catch (err: any) {
            const errMsg = err instanceof Error ? err.message : String(err);
            AccountAuthController.log('register', '❌ 注册异常', { error: errMsg });
            return AccountAuthController.withCors(
                createResponse(500, `注册失败: ${errMsg}`),
                request,
                env
            );
        }
    }

    /* ──────────── 2. 账号登录 ──────────── */

    static async loginWithAccount(request: Request, env: Env): Promise<Response> {
        AccountAuthController.log('loginWithAccount', '收到账号登录请求');

        if (request.method !== 'POST') {
            return AccountAuthController.withCors(
                createResponse(405, 'Method Not Allowed'),
                request,
                env
            );
        }

        try {
            let body: any;
            try {
                body = await request.json();
            } catch {
                return AccountAuthController.withCors(
                    createResponse(400, '请求体必须是有效的 JSON'),
                    request,
                    env
                );
            }

            const { username, email, password } = body;

            // 必须提供 username 或 email 之一，以及 password
            if (!password || (!username && !email)) {
                AccountAuthController.log('loginWithAccount', '❌ 缺少必要参数');
                return AccountAuthController.withCors(
                    createResponse(400, '缺少必要参数: 需要提供 (username 或 email) 和 password'),
                    request,
                    env
                );
            }

            // 查询用户
            AccountAuthController.log('loginWithAccount', '查询用户', { username, email });
            let user: any;
            if (username) {
                user = await env.DB
                    .prepare(
                        `SELECT user_id, username, email, password_hash, nickname FROM users 
                         WHERE username = ?1 AND auth_type = 'account'`
                    )
                    .bind(username)
                    .first();
            } else {
                user = await env.DB
                    .prepare(
                        `SELECT user_id, username, email, password_hash, nickname FROM users 
                         WHERE email = ?1 AND auth_type = 'account'`
                    )
                    .bind(email)
                    .first();
            }

            if (!user) {
                AccountAuthController.log('loginWithAccount', '❌ 用户不存在', { username, email });
                return AccountAuthController.withCors(
                    createResponse(401, '用户名/邮箱或密码错误'),
                    request,
                    env
                );
            }

            // 验证密码
            AccountAuthController.log('loginWithAccount', '验证密码', { user_id: user.user_id });
            const passwordValid = await verifyPassword(password, user.password_hash);

            if (!passwordValid) {
                AccountAuthController.log('loginWithAccount', '❌ 密码错误', { user_id: user.user_id });
                return AccountAuthController.withCors(
                    createResponse(401, '用户名/邮箱或密码错误'),
                    request,
                    env
                );
            }

            AccountAuthController.log('loginWithAccount', '✅ 密码验证成功', { user_id: user.user_id });

            // 签发 JWT
            const now = Math.floor(Date.now() / 1000);
            const exp = now + 7 * 24 * 3600;
            AccountAuthController.log('loginWithAccount', '签发 JWT', { user_id: user.user_id, iat: now, exp });
            const jwt = await signJwt(
                { userId: user.user_id, username: user.username, iat: now, exp },
                env.JWT_SECRET,
            );

            // Set-Cookie
            const cookieParts = [
                `token=${jwt}`,
                'Path=/',
                'HttpOnly',
                'Secure',
                'SameSite=Lax',
                `Max-Age=${7 * 24 * 3600}`,
            ];
            if (env.COOKIE_DOMAIN) {
                cookieParts.push(`Domain=${env.COOKIE_DOMAIN}`);
            }
            const cookie = cookieParts.join('; ');

            const resp = createResponse(200, 'success', {
                user_id: user.user_id,
                username: user.username,
                email: user.email,
                nickname: user.nickname,
                message: '登录成功',
            });
            const headers = new Headers(resp.headers);
            headers.append('Set-Cookie', cookie);

            return AccountAuthController.withCors(
                new Response(resp.body, { status: resp.status, headers }),
                request,
                env
            );
        } catch (err: any) {
            const errMsg = err instanceof Error ? err.message : String(err);
            AccountAuthController.log('loginWithAccount', '❌ 登录异常', { error: errMsg });
            return AccountAuthController.withCors(
                createResponse(500, `登录失败: ${errMsg}`),
                request,
                env
            );
        }
    }
}
