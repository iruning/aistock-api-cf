/**
 * 密码加密和验证工具
 * 基于 Web Crypto API，使用 PBKDF2
 */

function base64Encode(data: Uint8Array): string {
    let binary = '';
    for (const byte of data) {
        binary += String.fromCharCode(byte);
    }
    return btoa(binary);
}

function base64Decode(str: string): Uint8Array {
    const binary = atob(str);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

function textEncode(text: string): Uint8Array {
    return new TextEncoder().encode(text);
}

/**
 * 生成随机盐值（32字节）
 */
function generateSalt(): Uint8Array {
    return crypto.getRandomValues(new Uint8Array(32));
}

/**
 * 使用 PBKDF2 对密码进行哈希处理
 * 返回格式: "salt:hash"（base64编码）
 * @param password 明文密码
 * @returns base64编码的 "salt:hash"
 */
export async function hashPassword(password: string): Promise<string> {
    const salt = generateSalt();
    
    // 导入密钥
    const key = await crypto.subtle.importKey(
        'raw',
        textEncode(password),
        'PBKDF2',
        false,
        ['deriveBits']
    );

    // PBKDF2 衍生密钥：100,000 迭代，SHA-256，256位输出
    const derivedBits = await crypto.subtle.deriveBits(
        {
            name: 'PBKDF2',
            salt: salt,
            iterations: 100000,
            hash: 'SHA-256',
        },
        key,
        256
    );

    const hash = new Uint8Array(derivedBits);
    const combined = new Uint8Array(salt.length + hash.length);
    combined.set(salt);
    combined.set(hash, salt.length);

    return base64Encode(combined);
}

/**
 * 验证密码
 * @param password 明文密码
 * @param hashedPassword 存储的哈希值（format: "salt:hash"）
 * @returns 密码是否匹配
 */
export async function verifyPassword(password: string, hashedPassword: string): Promise<boolean> {
    try {
        const combined = base64Decode(hashedPassword);
        const salt = combined.slice(0, 32);
        const storedHash = combined.slice(32);

        // 用同样的盐和迭代次数重新计算
        const key = await crypto.subtle.importKey(
            'raw',
            textEncode(password),
            'PBKDF2',
            false,
            ['deriveBits']
        );

        const derivedBits = await crypto.subtle.deriveBits(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: 100000,
                hash: 'SHA-256',
            },
            key,
            256
        );

        const computedHash = new Uint8Array(derivedBits);

        // 常时间比较，防止时序攻击
        let match = true;
        if (computedHash.length !== storedHash.length) {
            match = false;
        } else {
            for (let i = 0; i < computedHash.length; i++) {
                if (computedHash[i] !== storedHash[i]) {
                    match = false;
                }
            }
        }

        return match;
    } catch (err) {
        console.error('[Password] 验证密码异常:', err);
        return false;
    }
}

/**
 * 验证邮箱格式
 */
export function isValidEmail(email: string): boolean {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email) && email.length <= 255;
}

/**
 * 验证用户名格式（字母、数字、下划线、连字符，3-32字符）
 */
export function isValidUsername(username: string): boolean {
    return /^[a-zA-Z0-9_-]{3,32}$/.test(username);
}

/**
 * 验证密码强度（至少8字符，包含字母和数字）
 */
export function isValidPassword(password: string): boolean {
    return password.length >= 8 && /[a-zA-Z]/.test(password) && /[0-9]/.test(password);
}
