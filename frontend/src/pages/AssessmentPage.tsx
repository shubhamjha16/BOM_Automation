import { useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { NarrativePanel } from '@/features/narrative';
import { downloadExport, useAssessment, type ExportFormat } from '@/features/assessments';
import { ROUTES } from '@/shared/constants/routes';
import { formatScore } from '@/utils/format';

const FORMATS: ExportFormat[] = ['xlsx', 'docx', 'json', 'pdf'];

export function AssessmentPage() {
  const { id = '' } = useParams();
  const { data, isPending, error } = useAssessment(id);
  const [exportError, setExportError] = useState<string | null>(null);

  if (isPending) return <p>Building the assessment…</p>;
  if (error) return <p role="alert">Could not load the assessment.</p>;

  const download = async (format: ExportFormat) => {
    setExportError(null);
    try {
      await downloadExport(id, format);
    } catch (failure) {
      setExportError(failure instanceof Error ? failure.message : 'Export failed');
    }
  };

  return (
    <section>
      {/* Never hidden: a draft that looks issued will be read as issued. */}
      {data.watermark && (
        <p className="watermark" role="status">
          {data.watermark}
        </p>
      )}

      <header className="detail__head">
        <div>
          <h1>Conformance assessment</h1>
          <p className="detail__meta">
            Overall {formatScore(data.overall_score)} · status {data.status}
          </p>
        </div>
        <div className="exports">
          {FORMATS.map((format) => (
            <button key={format} type="button" onClick={() => download(format)}>
              {format.toUpperCase()}
            </button>
          ))}
        </div>
      </header>

      {exportError && (
        <p role="alert" className="auth__error">
          {exportError}
        </p>
      )}

      {data.sections.map((section) => (
        <article key={section.ord} className="section">
          <h2>{section.title}</h2>
          <pre className="section__body">{section.content}</pre>
          {(section.field_verdict_ids.length > 0 ||
            section.correlation_finding_ids.length > 0) && (
            <p className="section__provenance">
              Written from {section.field_verdict_ids.length} field verdict(s)
              {section.correlation_finding_ids.length > 0 &&
                ` and ${section.correlation_finding_ids.length} cross-document finding(s)`}
              .
            </p>
          )}
        </article>
      ))}

      <NarrativePanel submissionId={id} />

      <p>
        <Link to={ROUTES.submission(id)}>← Back to submission</Link>
      </p>
    </section>
  );
}
