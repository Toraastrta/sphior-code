/**
 * interproc.ts — 言語非依存の multi-level inter-procedural taint エンジン
 *
 * 各 tree-sitter バックエンドは言語固有のアダプタ（collectFunctions/collectTainted/
 * scanSinks/exprTainted/callTarget/walkScope）を渡すだけで、関数サマリ(param→sink)を
 * call graph 上で fixpoint 伝播（2 段以上）＋ intra/inter sink 報告を共有する。
 * fixpoint ロジックを言語ごとに複製しない。
 */

export interface INode {
  type: string;
  text: string;
  startPosition: { row: number; column: number };
  endPosition: { row: number; column: number };
  childCount: number;
  child(i: number): INode | null;
  namedChildCount: number;
  namedChild(i: number): INode | null;
  childForFieldName(name: string): INode | null;
}

export interface Hit {
  ruleId: string;
  node: INode;
}

export interface InterProcLang {
  root: INode;
  /** module/ファイルスコープのノード型（例: "source_file"/"program"/"compilation_unit"）。 */
  moduleType: string;
  /** 関数スコープ境界のノード型。 */
  scopeTypes: Set<string>;
  collectFunctions(root: INode): Map<string, { params: string[]; scope: INode }>;
  collectTainted(scope: INode, seed: Iterable<string>): Set<string>;
  scanSinks(scope: INode, tainted: Set<string>): Hit[];
  exprTainted(node: INode | null, tainted: Set<string>): boolean;
  /** call ノードなら { ローカル関数名, 位置引数 } を返す（それ以外 null）。 */
  callTarget(node: INode): { callee: string; posArgs: (INode | null)[] } | null;
  walkScope(scope: INode, visit: (n: INode) => void): void;
}

const hitKey = (h: Hit): string => `${h.ruleId}@${h.node.startPosition.row}:${h.node.startPosition.column}`;

/** multi-level inter-procedural taint を実行し、finding を add で報告する。 */
export function runInterProcTaint(lang: InterProcLang, add: (ruleId: string, node: INode) => void): void {
  const { root } = lang;
  const functions = lang.collectFunctions(root);

  // 1) 関数サマリ（param i が sink へ到達するか）を fixpoint で多段伝播
  const paramSinks = new Map<string, Map<number, Hit[]>>();
  let changed = true;
  let guard = 0;
  while (changed && guard++ < functions.size + 5) {
    changed = false;
    for (const [name, fn] of functions) {
      fn.params.forEach((p, i) => {
        if (!p) return;
        const tainted = lang.collectTainted(fn.scope, [p]);
        const hits: Hit[] = [...lang.scanSinks(fn.scope, tainted)];
        lang.walkScope(fn.scope, (n) => {
          const t = lang.callTarget(n);
          if (!t || t.callee === name) return;
          const cps = paramSinks.get(t.callee);
          if (!cps) return;
          for (const [j, chits] of cps) if (lang.exprTainted(t.posArgs[j] ?? null, tainted)) hits.push(...chits);
        });
        if (!hits.length) return;
        let per = paramSinks.get(name);
        if (!per) { per = new Map(); paramSinks.set(name, per); }
        const ex = per.get(i) ?? [];
        const keys = new Set(ex.map(hitKey));
        let added = false;
        for (const h of hits) if (!keys.has(hitKey(h))) { ex.push(h); keys.add(hitKey(h)); added = true; }
        if (added) { per.set(i, ex); changed = true; }
      });
    }
  }

  // 2) スコープ群（module + 各関数）で intra-proc sink ＋ inter-proc 呼び出しを報告
  const scopes: INode[] = [];
  const collect = (n: INode): void => {
    if (n.type === lang.moduleType || lang.scopeTypes.has(n.type)) scopes.push(n);
    for (let i = 0; i < n.childCount; i++) { const c = n.child(i); if (c) collect(c); }
  };
  collect(root);

  for (const scope of scopes) {
    const tainted = lang.collectTainted(scope, []);
    for (const h of lang.scanSinks(scope, tainted)) add(h.ruleId, h.node);
    lang.walkScope(scope, (n) => {
      const t = lang.callTarget(n);
      if (!t) return;
      const per = paramSinks.get(t.callee);
      if (!per) return;
      for (const [j, hits] of per) if (lang.exprTainted(t.posArgs[j] ?? null, tainted)) for (const h of hits) add(h.ruleId, h.node);
    });
  }
}
