import { signJwt } from '../utils/jwt';
import { verifyPassword } from '../utils/password';
import { createResponse } from '../utils/response';
import type { Env } from '../index';

/**
 * 账密登录控制器
 *
 * 流程:
 *  1. POST /api/auth/login/password { email/username, password }
 *  2. 从 D1 查询用户
 *  3. 验证密码
 *  4. 签发 JWT
 *  5. Set-Cookie + 返回 JWT
 */
export class CredentialAuthController {

    private static log(stage: string, message: string, data?: any): void {
        const ts = new Date().toISOString();
        const detail = data !== undefined ? ` | ${JSON.stringify(data)}` : '';
        console.log(`[CredentialAuth][${stage}] ${ts} ${message}${detail}`);
    }

    static async login(request: Request, env: Env): Promise<Response> {
        CredentialAuthController.log('start', '收到账密登录请求', { url: request.url });

        if (request.method !== 'POST') {
            return createResponse(405, 'Method Not Allowed');
        }

        try {
            let body: any;
            try {
                body = await request.json();
            } catch {
                CredentialAuthController.log('parse', '❌ JSON 解析失败');
                return createResponse(400, '请求体必须是有效的 JSON');
            }

            const { email, username, password } = body;

            /* ─────────────────── 1. 参数校验 ─────────────────── */

            if (!password || typeof password !== 'string') {
                CredentialAuthController.log('validate', '❌ 缺少 password 参数');
                return createResponse(400, '缺少 password 参数');
            }

            if (!email && !username) {
                CredentialAuthController.log('validate', '❌ 缺少 email 或 username 参数');
                return createResponse(400, '缺少 email 或 username 参数');
            }

            const loginIdentifier = email || username;
            const isEmail = !!email;

            CredentialAuthController.log('validate', '✅ 参数校验通过', { isEmail, identifier: loginIdentifier });

            /* ─────────────────── 2. 从 D1 查询用户 ─────────────────── */

            CredentialAuthController.log('query', '开始查询用户', { isEmail, identifier: loginIdentifier });

            const user = await env.DB
                .prepare(
                    isEmail
                        ? 'SELECT id, email, username, password_hash, nickname, avatar_url, auth_method, created_at FROM users WHERE email = ?1 LIMIT 1'
                        : 'SELECT id, email, username, password_hash, nickname, avatar_url, auth_method, created_at FROM users WHERE username = ?1 LIMIT 1'
                )
                .bind(loginIdentifier)
                .first<any>();

            if (!user) {
                CredentialAuthController.log('query', '❌ 用户不存在', { isEmail, identifier: loginIdentifier });
                return createResponse(401, '邮箱/用户名或密码错误');
            }

            if (!user.password_hash) {
                CredentialAuthController.log('query', '❌ 用户无密码（可能为微信登录账户）', { userId: user.id });
                return createResponse(401, '该账户未设置密码，请使用微信登录');
            }

            CredentialAuthController.log('query', '✅ 用户查询成功', { userId: user.id, username: user.username });

            /* ─────────────────── 3. 验证密码 ─────────────────── */

            CredentialAuthController.log('verify', '开始验证密码', { userId: user.id });
            const passwordValid = await verifyPassword(password, user.password_hash);

            if (!passwordValid) {
                CredentialAuthController.log('verify', '❌ 密码验证失败', { userId: user.id });
                return createResponse(401, '邮箱/用户名或密码错误');
            }

            CredentialAuthController.log('verify', '✅ 密码验证成功', { userId: user.id });

            /* ─────────────────── 4. 签发 JWT ─────────────────── */

            CredentialAuthController.log('jwt', '开始签发 JWT', { userId: user.id });
            const now = Math.floor(Date.now() / 1000);
            const exp = now + 7 * 24 * 3600;

            const jwt = await signJwt(
                {
                    userId: user.id,
                    email: user.email,
                    username: user.username,
                    nickname: user.nickname || user.username,
                    auth_method: user.auth_method || 'password',
                    iat: now,
                    exp,
                },
                env.JWT_SECRET,
            );

            CredentialAuthController.log('jwt', '✅ JWT 签发成功', { userId: user.id, tokenLength: jwt.length });

            /* ─────────────────── 5. 设置 Cookie ─────────────────── */

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

            CredentialAuthController.log('response', '✅ 登录成功，返回 JWT', { userId: user.id });

            const resp = createResponse(200, 'success', {
                user: {
                    id: user.id,
                    email: user.email,
                    username: user.username,
                    nickname: user.nickname || user.username,
                    avatar_url: user.avatar_url || '',
                    auth_method: user.auth_method || 'password',
                    created_at: user.created_at,
                },
                token: jwt,
            });

            const headers = new Headers(resp.headers);
            headers.append('Set-Cookie', cookie);

            return new Response(resp.body, { status: resp.status, headers });

        } catch (err: any) {
            const errMsg = err instanceof Error ? err.message : String(err);
            const errStack = err instanceof Error ? err.stack : undefined;
            CredentialAuthController.log('error', '❌ 登录流程异常', { error: errMsg, stack: errStack });
            return createResponse(500, `登录失败: ${errMsg}`);
        }
    }
}
