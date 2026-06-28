import { signJwt } from '../utils/jwt';
import { hashPassword, isValidEmail, isValidUsername, isValidPassword } from '../utils/password';
import { createResponse } from '../utils/response';
import type { Env } from '../index';

/**
 * 注册控制器 - 支持邮箱/用户名注册
 *
 * 流程:
 *  1. POST /api/auth/register { email, username, password }
 *  2. 验证邮箱、用户名、密码格式
 *  3. 检查邮箱/用户名是否已存在
 *  4. 密码 PBKDF2 哈希
 *  5. 插入 D1 users 表（auth_method='password'）
 *  6. 签发 JWT
 *  7. Set-Cookie + 302 或 200 JSON 响应
 */
export class RegisterController {

    private static log(stage: string, message: string, data?: any): void {
        const ts = new Date().toISOString();
        const detail = data !== undefined ? ` | ${JSON.stringify(data)}` : '';
        console.log(`[Register][${stage}] ${ts} ${message}${detail}`);
    }

    static async register(request: Request, env: Env): Promise<Response> {
        RegisterController.log('start', '收到注册请求', { url: request.url });

        if (request.method !== 'POST') {
            return createResponse(405, 'Method Not Allowed');
        }

        try {
            let body: any;
            try {
                body = await request.json();
            } catch {
                RegisterController.log('parse', '❌ JSON 解析失败');
                return createResponse(400, '请求体必须是有效的 JSON');
            }

            const { email, username, password } = body;

            /* ─────────────────── 1. 参数校验 ─────────────────── */

            if (!email || typeof email !== 'string') {
                RegisterController.log('validate', '❌ 缺少 email 参数');
                return createResponse(400, '缺少 email 参数');
            }

            if (!username || typeof username !== 'string') {
                RegisterController.log('validate', '❌ 缺少 username 参数');
                return createResponse(400, '缺少 username 参数');
            }

            if (!password || typeof password !== 'string') {
                RegisterController.log('validate', '❌ 缺少 password 参数');
                return createResponse(400, '缺少 password 参数');
            }

            const trimEmail = email.trim();
            const trimUsername = username.trim();

            /* ─────────────────── 2. 格式校验 ─────────────────── */

            if (!isValidEmail(trimEmail)) {
                RegisterController.log('validate', '❌ 邮箱格式无效', { email: trimEmail });
                return createResponse(400, '邮箱格式无效');
            }

            if (!isValidUsername(trimUsername)) {
                RegisterController.log('validate', '❌ 用户名格式无效（3-32字符，仅支持字母/数字/_/-）', { username: trimUsername });
                return createResponse(400, '用户名格式无效（3-32字符，仅支持字母/数字/_/-）');
            }

            if (!isValidPassword(password)) {
                RegisterController.log('validate', '❌ 密码强度不足（至少8字符，包含字母和数字）');
                return createResponse(400, '密码强度不足（至少8字符，包含字母和数字）');
            }

            RegisterController.log('validate', '✅ 格式校验通过', { email: trimEmail, username: trimUsername });

            /* ─────────────────── 3. 检查邮箱/用户名是否已存在 ─────────────────── */

            RegisterController.log('check', '开始检查邮箱/用户名重复');

            const existingByEmail = await env.DB
                .prepare('SELECT id FROM users WHERE email = ?1 LIMIT 1')
                .bind(trimEmail)
                .first();

            if (existingByEmail) {
                RegisterController.log('check', '❌ 邮箱已被注册', { email: trimEmail });
                return createResponse(409, '邮箱已被注册');
            }

            const existingByUsername = await env.DB
                .prepare('SELECT id FROM users WHERE username = ?1 LIMIT 1')
                .bind(trimUsername)
                .first();

            if (existingByUsername) {
                RegisterController.log('check', '❌ 用户名已被注册', { username: trimUsername });
                return createResponse(409, '用户名已被注册');
            }

            RegisterController.log('check', '✅ 邮箱/用户名未被注册');

            /* ─────────────────── 4. 密码哈希 ─────────────────── */

            RegisterController.log('hash', '开始密码哈希');
            const passwordHash = await hashPassword(password);
            RegisterController.log('hash', '✅ 密码哈希完成', { hashLength: passwordHash.length });

            /* ─────────────────── 5. 写入 D1 ─────────────────── */

            RegisterController.log('insert', '开始插入 D1 用户表', { email: trimEmail, username: trimUsername });

            const now = new Date().toISOString();
            const result = await env.DB
                .prepare(
                    `INSERT INTO users (email, username, password_hash, nickname, avatar_url, auth_method, created_at, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)`
                )
                .bind(trimEmail, trimUsername, passwordHash, trimUsername, '', 'password', now, now)
                .run();

            RegisterController.log('insert', '✅ D1 插入成功', { insertedId: result?.meta?.last_row_id });

            /* ─────────────────── 6. 签发 JWT ─────────────────── */

            RegisterController.log('jwt', '开始签发 JWT');
            const jwtNow = Math.floor(Date.now() / 1000);
            const jwtExp = jwtNow + 7 * 24 * 3600;

            const jwt = await signJwt(
                {
                    userId: result?.meta?.last_row_id,
                    email: trimEmail,
                    username: trimUsername,
                    nickname: trimUsername,
                    auth_method: 'password',
                    iat: jwtNow,
                    exp: jwtExp,
                },
                env.JWT_SECRET,
            );

            RegisterController.log('jwt', '✅ JWT 签发成功', { tokenLength: jwt.length });

            /* ─────────────────── 7. 设置 Cookie ─────────────────── */

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

            RegisterController.log('response', '✅ 注册成功，返回 JWT');

            const resp = createResponse(200, 'success', {
                user: {
                    id: result?.meta?.last_row_id,
                    email: trimEmail,
                    username: trimUsername,
                    nickname: trimUsername,
                    avatar_url: '',
                    auth_method: 'password',
                    created_at: now,
                },
                token: jwt,
            });

            const headers = new Headers(resp.headers);
            headers.append('Set-Cookie', cookie);

            return new Response(resp.body, { status: resp.status, headers });

        } catch (err: any) {
            const errMsg = err instanceof Error ? err.message : String(err);
            const errStack = err instanceof Error ? err.stack : undefined;
            RegisterController.log('error', '❌ 注册流程异常', { error: errMsg, stack: errStack });
            return createResponse(500, `注册失败: ${errMsg}`);
        }
    }
}
