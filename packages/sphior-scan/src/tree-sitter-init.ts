/**
 * tree-sitter-init.ts — web-tree-sitter の共有初期化（言語間で runtime を1回だけ init）
 *
 * Parser.init()（runtime WASM）は一度だけ実行し、各言語は grammar WASM を load して
 * parser を得る。WASM は base64 同梱（gen-wasm.mjs）で自己完結。
 */

/* eslint-disable @typescript-eslint/no-explicit-any */
import * as wts from "web-tree-sitter";
import { TS_RUNTIME_WASM_B64 } from "./gen/wasm-blobs";

export function b64ToBytes(b64: string): Uint8Array {
  return new Uint8Array(Buffer.from(b64, "base64"));
}

let init: Promise<{ Parser: any; Language: any }> | null = null;

function getTreeSitter(): Promise<{ Parser: any; Language: any }> {
  if (!init) {
    init = (async () => {
      const mod = wts as any;
      const Parser = mod.Parser ?? mod.default ?? mod;
      const Language = mod.Language ?? Parser.Language;
      await Parser.init({ wasmBinary: b64ToBytes(TS_RUNTIME_WASM_B64) });
      return { Parser, Language };
    })();
  }
  return init;
}

/** grammar WASM(base64) を load して parser を返す。 */
export async function loadParser(grammarB64: string): Promise<{ parse(s: string): { rootNode: any } }> {
  const { Parser, Language } = await getTreeSitter();
  const parser = new Parser();
  const lang = await Language.load(b64ToBytes(grammarB64));
  parser.setLanguage(lang);
  return parser;
}
