import fs from "fs/promises";
import path from "path";
import crypto from "crypto";
import { existsSync } from "fs";

export interface ProofResult {
  proofJSON: string;
  verificationKeyJSON: string;
}

export interface ProofCacheOptions {
  cacheDir?: string;
  prefixLength?: number;
}

export class ProofCache {
  private cacheDir: string;
  private prefixLength: number;

  constructor(options: ProofCacheOptions = {}) {
    this.cacheDir = options.cacheDir || path.join(process.cwd(), ".proofcache");
    this.prefixLength = options.prefixLength || 12;
  }

  /**
   * Get or generate proof based on source file and cache key
   * @param sourceFilePath Path to the source file
   * @param cacheKey Additional value that uniquely identifies the proof (string, Uint8Array, etc.)
   * @param generator Async function that generates proof and verification key
   * @returns Promise resolving to the proof result
   */
  async getProof(
    sourceFilePath: string,
    cacheKey: string | Uint8Array | Buffer | object | undefined,
    generator: () => Promise<ProofResult>,
  ): Promise<ProofResult> {
    await this.ensureCacheDir();

    // Combine file hash and cache key for a composite hash
    const sourceFileHash = await this.getFileHash(sourceFilePath);
    const combinedHash = await this.getCombinedHash(sourceFileHash, cacheKey);
    const cacheDir = this.getCacheDir(combinedHash);

    // Check if cache exists
    if (await this.isCacheValid(cacheDir)) {
      try {
        return await this.readFromCache(cacheDir);
      } catch (error) {
        // If reading fails, regenerate
        console.warn("Cache read failed, regenerating:", error);
      }
    }

    // Generate new proof
    const result = await generator();
    await this.writeToCache(cacheDir, result);
    return result;
  }

  /**
   * Invalidate cache for a specific file and cache key
   * @param sourceFilePath Path to the source file
   * @param cacheKey Additional cache key used when generating the proof
   */
  async invalidateCache(
    sourceFilePath: string,
    cacheKey?: string | Uint8Array | Buffer | object,
  ): Promise<void> {
    const sourceFileHash = await this.getFileHash(sourceFilePath);
    const combinedHash = await this.getCombinedHash(sourceFileHash, cacheKey);
    const cacheDir = this.getCacheDir(combinedHash);

    if (existsSync(cacheDir)) {
      await fs.rm(cacheDir, { recursive: true, force: true });
    }
  }

  /**
   * Clear the entire cache
   */
  async clearCache(): Promise<void> {
    try {
      if (existsSync(this.cacheDir)) {
        await fs.rm(this.cacheDir, { recursive: true, force: true });
        await this.ensureCacheDir();
      }
    } catch (error) {
      console.error("Failed to clear cache:", error);
      throw error;
    }
  }

  /**
   * Combine the file hash with an optional cache key
   */
  private async getCombinedHash(
    fileHash: string,
    cacheKey?: string | Uint8Array | Buffer | object,
  ): Promise<string> {
    if (!cacheKey) {
      return fileHash;
    }

    const keyHash = this.hashCacheKey(cacheKey);
    return crypto
      .createHash("sha256")
      .update(`${fileHash}:${keyHash}`)
      .digest("hex");
  }

  /**
   * Hash a cache key to create a deterministic identifier
   */
  private hashCacheKey(
    cacheKey: string | Uint8Array | Buffer | object,
  ): string {
    const hash = crypto.createHash("sha256");

    if (typeof cacheKey === "string") {
      hash.update(cacheKey);
    } else if (cacheKey instanceof Uint8Array || Buffer.isBuffer(cacheKey)) {
      hash.update(Buffer.from(cacheKey));
    } else if (typeof cacheKey === "object") {
      hash.update(JSON.stringify(cacheKey));
    } else {
      throw new Error("Unsupported cache key type");
    }

    return hash.digest("hex");
  }

  private async ensureCacheDir(): Promise<void> {
    try {
      await fs.mkdir(this.cacheDir, { recursive: true });
    } catch (error) {
      // Ignore if directory already exists
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") {
        throw error;
      }
    }
  }

  private async getFileHash(filePath: string): Promise<string> {
    const content = await fs.readFile(filePath);
    return crypto.createHash("sha256").update(content).digest("hex");
  }

  private getCacheDir(hash: string): string {
    const prefix = hash.substring(0, this.prefixLength);
    return path.join(this.cacheDir, prefix);
  }

  private async isCacheValid(cacheDir: string): Promise<boolean> {
    try {
      const proofPath = path.join(cacheDir, "proof.json");
      const vkPath = path.join(cacheDir, "verification-key.json");

      return existsSync(proofPath) && existsSync(vkPath);
    } catch (error) {
      return false;
    }
  }

  private async readFromCache(cacheDir: string): Promise<ProofResult> {
    const proofPath = path.join(cacheDir, "proof.json");
    const vkPath = path.join(cacheDir, "verification-key.json");

    const [proof, verificationKey] = await Promise.all([
      fs.readFile(proofPath, "utf8"),
      fs.readFile(vkPath, "utf8"),
    ]);

    return { proofJSON: proof, verificationKeyJSON: verificationKey };
  }

  private async writeToCache(
    cacheDir: string,
    result: ProofResult,
  ): Promise<void> {
    // Ensure the directory exists
    await fs.mkdir(cacheDir, { recursive: true });

    const proofPath = path.join(cacheDir, "proof.json");
    const vkPath = path.join(cacheDir, "verification-key.json");

    await Promise.all([
      fs.writeFile(proofPath, result.proofJSON, "utf8"),
      fs.writeFile(vkPath, result.verificationKeyJSON, "utf8"),
    ]);
  }
}
