import { formatScore } from '@/utils/format';

/** A null score renders as an em dash. The console never invents a figure. */
export function ScoreDial({ score, label }: { score: number | null; label: string }) {
  return (
    <div className="score-dial" data-score={score ?? 'none'}>
      <strong>{formatScore(score)}</strong>
      <span>{label}</span>
    </div>
  );
}
