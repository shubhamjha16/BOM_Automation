/**
 * S20: component names are supplier-controlled text, and this console renders them.
 *
 * The protection is real — React escapes by default and `dangerouslySetInnerHTML`
 * appears nowhere in `src/` — but until now that was a property verified by grep
 * and defended by nothing. A single future component could reintroduce it and pass
 * review, because nothing would fail.
 *
 * Two tests, because they catch different failures:
 *
 * 1. **Rendering** — put real payloads through the components that display
 *    supplier text and assert they surface as visible characters rather than
 *    executing. This is the property a client actually depends on.
 * 2. **An AST guard over the whole of `src/`** — because a rendering test only
 *    covers the components it names, and the component that reintroduces the hole
 *    is by definition one nobody thought to test.
 *
 * A grep would not do for the second: `dangerouslySetInnerHTML` appears in this
 * file's own prose, and a source-text match on its own documentation is a mistake
 * already made three times in the backend suite.
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { parse } from '@typescript-eslint/typescript-estree';
import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import { ClauseRef } from '@/components/conformance/ClauseRef';
import { ElementTable } from '@/features/elements/components/ElementTable';
import { QuotaExceededState } from '@/features/quota';
import type { MinimumElement } from '@/features/elements/services/elementsApi';

/**
 * Payloads chosen for how they actually arrive, not for novelty. Each is text a
 * supplier can legitimately put in a CycloneDX `name` or `supplier.name` field —
 * the BOM parser has no reason to reject any of them, so the console must be the
 * thing that renders them inert.
 */
const PAYLOADS = [
  '<script>window.__xss = true</script>',
  '<img src=x onerror="window.__xss = true">',
  '"><svg/onload=alert(1)>',
  "javascript:window.__xss = true",
  '<iframe src="javascript:window.__xss=true"></iframe>',
  '{{constructor.constructor("window.__xss=true")()}}',
];

function element(label: string): MinimumElement {
  return {
    key: 'component_name',
    label,
    clause: '4.2(1)',
    tier: 'critical',
    determinability: 'auto',
    scores_against_supplier: true,
  } as MinimumElement;
}

describe('supplier-controlled text renders inert', () => {
  it.each(PAYLOADS)('a component label containing %s does not execute', (payload) => {
    delete (window as unknown as Record<string, unknown>).__xss;

    const { container } = render(<ElementTable elements={[element(payload)]} />);

    // The payload is present as *text*, which is correct — a supplier who named
    // a component `<script>` should see that name in the report, not a blank cell.
    expect(container.textContent).toContain(payload);
    // And it did not become part of the document.
    expect((window as unknown as Record<string, unknown>).__xss).toBeUndefined();
    expect(container.querySelector('script')).toBeNull();
    expect(container.querySelector('iframe')).toBeNull();
    expect(container.querySelector('img')).toBeNull();
    expect(container.querySelector('svg')).toBeNull();
  });

  it('a payload in a clause reference does not reach an attribute unescaped', () => {
    /* `ClauseRef` puts its input in a `data-clause` attribute. An attribute is a
       second injection surface with different escaping rules from a text node, so
       it is worth its own case. */
    const { container } = render(<ClauseRef clause={'" onmouseover="window.__xss=1'} />);
    const abbr = container.querySelector('abbr');

    expect(abbr).not.toBeNull();
    expect(abbr?.getAttribute('onmouseover')).toBeNull();
    expect(abbr?.getAttribute('data-clause')).toContain('onmouseover');
  });

  it('a quota remedy from the server renders inert', () => {
    /* The 429 body is server-authored rather than supplier-authored, so this is a
       weaker threat — but the console does not know that, and a compromised or
       proxied API is exactly the case where it matters. */
    render(
      <QuotaExceededState
        refusal={{
          detail: 'd',
          quota: 'submissions_per_month',
          limit: 25,
          used: 25,
          plan: '<script>window.__xss=1</script>',
          resets_at: null,
          retry_after_seconds: 0,
          remedy: '<img src=x onerror="window.__xss=1">',
        }}
      />,
    );

    expect((window as unknown as Record<string, unknown>).__xss).toBeUndefined();
    expect(screen.getByRole('status').querySelector('img')).toBeNull();
  });

  it('a very long supplier name does not break the render', () => {
    /* Not a security case — a correctness one. A 40,000-character component name
       is a plausible generator bug, and a table that throws on it takes the whole
       assessment view down. */
    const { container } = render(<ElementTable elements={[element('A'.repeat(40_000))]} />);
    expect(container.textContent?.length).toBeGreaterThan(40_000);
  });
});

// --- the guard that covers components nobody thought to test -----------------

function sourceFiles(directory: string): string[] {
  return readdirSync(directory).flatMap((entry) => {
    const path = join(directory, entry);
    if (statSync(path).isDirectory()) return sourceFiles(path);
    return /\.(ts|tsx)$/.test(entry) ? [path] : [];
  });
}

/**
 * Every JSX attribute name in a file, with the line it sits on.
 *
 * `jsx` is set from the extension rather than passed as `true` throughout: a `.ts`
 * file parsed as JSX chokes on a generic type parameter, because `<T>` is
 * ambiguous between a type argument and an element. Getting this wrong produced a
 * parse error that looked like a syntax problem in the source under test.
 */
function jsxAttributes(source: string, file: string): { name: string; line: number }[] {
  const tree = parse(source, { jsx: file.endsWith('.tsx'), loc: true });
  const found: { name: string; line: number }[] = [];

  const walk = (node: unknown): void => {
    if (node === null || typeof node !== 'object') return;
    const record = node as Record<string, unknown>;
    if (record.type === 'JSXAttribute') {
      const name = record.name as { name?: string } | undefined;
      const loc = record.loc as { start: { line: number } } | undefined;
      if (name?.name) found.push({ name: name.name, line: loc?.start.line ?? 0 });
    }
    for (const value of Object.values(record)) {
      if (Array.isArray(value)) value.forEach(walk);
      else walk(value);
    }
  };

  walk(tree);
  return found;
}

describe('no component can reintroduce an injection surface', () => {
  const files = sourceFiles(join(process.cwd(), 'src'));

  it('finds the source tree', () => {
    expect(files.length).toBeGreaterThan(20);
  });

  it('nothing in src/ sets dangerouslySetInnerHTML', () => {
    /* Checked on the AST rather than the source text. A grep matches this file's
       own documentation and the backend suite has made that mistake three times —
       identifiers only. */
    const offenders = files.flatMap((file) =>
      jsxAttributes(readFileSync(file, 'utf8'), file)
        .filter((attribute) => attribute.name === 'dangerouslySetInnerHTML')
        .map((attribute) => `${file}:${attribute.line}`),
    );

    expect(offenders).toEqual([]);
  });

  it('no href or src is built from an interpolated value without a scheme', () => {
    /* `href={someValue}` where the value is supplier-controlled is a
       `javascript:` URL waiting to happen — React escapes text but does not
       validate URL schemes. Flags the pattern so a reviewer has to think about
       it, rather than blocking interpolation outright. */
    const suspicious = files.flatMap((file) => {
      const source = readFileSync(file, 'utf8');
      return [...source.matchAll(/\b(href|src)=\{([^}]*)\}/g)]
        .filter(([, , expression]) => /\b(url|link|ref|source)\b/i.test(expression))
        .map(([match]) => `${file}: ${match}`);
    });

    expect(suspicious).toEqual([]);
  });
});
