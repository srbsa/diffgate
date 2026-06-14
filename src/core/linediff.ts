export function computeChangedLines(
  oldText: string | null,
  newText: string,
  opts: { maxCells?: number } = {}
): Set<number> | null {
  if (oldText == null) return null;
  const oldLines = oldText.split("\n");
  const newLines = newText.split("\n");
  const N = oldLines.length;
  const M = newLines.length;

  const maxCells = opts.maxCells || 4_000_000;
  if (N * M > maxCells) {
    const all = new Set<number>();
    for (let i = 1; i <= M; i++) all.add(i);
    return all;
  }

  const dp: Uint32Array[] = Array.from({ length: N + 1 }, () => new Uint32Array(M + 1));
  for (let i = N - 1; i >= 0; i--) {
    for (let j = M - 1; j >= 0; j--) {
      dp[i][j] =
        oldLines[i] === newLines[j]
          ? dp[i + 1][j + 1] + 1
          : Math.max(dp[i + 1][j], dp[i][j + 1]);
    }
  }

  const changed = new Set<number>();
  let i = 0;
  let j = 0;
  while (i < N && j < M) {
    if (oldLines[i] === newLines[j]) {
      i++;
      j++;
    } else if (dp[i + 1][j] >= dp[i][j + 1]) {
      i++;
    } else {
      changed.add(j + 1);
      j++;
    }
  }
  while (j < M) {
    changed.add(j + 1);
    j++;
  }
  return changed;
}
