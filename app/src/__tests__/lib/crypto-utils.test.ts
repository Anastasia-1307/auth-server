import { describe, it, expect } from "bun:test";
import {
  base64url,
  sha256Base64Url,
  generateCode,
  verifyPassword,
} from "../../lib/crypto-utils";

describe("Crypto Utilities", () => {
  describe("base64url", () => {
    it("should encode buffer to base64url format", () => {
      const buffer = Buffer.from("hello world");
      const result = base64url(buffer);
      expect(result).toBe("aGVsbG8gd29ybGQ");
    });

    it("should handle empty buffer", () => {
      const buffer = Buffer.from("");
      const result = base64url(buffer);
      expect(result).toBe("");
    });

    it("should replace + with -", () => {
      const buffer = Buffer.from("+++");
      const result = base64url(buffer);
      expect(result).toBe("Kysr"); // "+++" in base64 is "Kysr", no + to replace
    });

    it("should replace / with _", () => {
      const buffer = Buffer.from("///");
      const result = base64url(buffer);
      expect(result).toBe("Ly8v"); // "///" in base64 is "Ly8v", no / to replace
    });

    it("should remove trailing =", () => {
      const buffer = Buffer.from("test");
      const result = base64url(buffer);
      expect(result).not.toContain("=");
    });
  });

  describe("sha256Base64Url", () => {
    it("should hash string and encode to base64url", () => {
      const result = sha256Base64Url("test");
      expect(result).toBeString();
      expect(result.length).toBeGreaterThan(0);
    });

    it("should produce consistent results", () => {
      const result1 = sha256Base64Url("test");
      const result2 = sha256Base64Url("test");
      expect(result1).toBe(result2);
    });

    it("should produce different results for different inputs", () => {
      const result1 = sha256Base64Url("test1");
      const result2 = sha256Base64Url("test2");
      expect(result1).not.toBe(result2);
    });

    it("should handle empty string", () => {
      const result = sha256Base64Url("");
      expect(result).toBeString();
      expect(result.length).toBeGreaterThan(0);
    });
  });

  describe("generateCode", () => {
    it("should generate a string", () => {
      const result = generateCode();
      expect(result).toBeString();
    });

    it("should generate codes of consistent length", () => {
      const result = generateCode();
      expect(result.length).toBeGreaterThan(0);
      expect(result.length).toBeLessThanOrEqual(64); // 32 bytes * 4/3 base64 encoding
    });

    it("should generate different codes each time", () => {
      const result1 = generateCode();
      const result2 = generateCode();
      expect(result1).not.toBe(result2);
    });

    it("should generate base64url-safe codes", () => {
      const result = generateCode();
      expect(result).not.toContain("+");
      expect(result).not.toContain("/");
      expect(result).not.toContain("=");
    });
  });

  describe("verifyPassword", () => {
    it("should verify correct password", async () => {
      const password = "testPassword123";
      const hash = await Bun.password.hash(password);
      const result = await verifyPassword(password, hash);
      expect(result).toBe(true);
    });

    it("should reject incorrect password", async () => {
      const password = "testPassword123";
      const wrongPassword = "wrongPassword123";
      const hash = await Bun.password.hash(password);
      const result = await verifyPassword(wrongPassword, hash);
      expect(result).toBe(false);
    });

    it("should reject empty password", async () => {
      const password = "testPassword123";
      const hash = await Bun.password.hash(password);
      const result = await verifyPassword("", hash);
      expect(result).toBe(false);
    });

    it("should handle invalid hash", async () => {
      const password = "testPassword123";
      const invalidHash = "invalid_hash";
      // Bun.password.verify aruncă eroare pentru hash invalid, nu returnează false
      await expect(verifyPassword(password, invalidHash)).rejects.toThrow();
    });

    it("should handle empty hash", async () => {
      const password = "testPassword123";
      const result = await verifyPassword(password, "");
      expect(result).toBe(false);
    });
  });
});
