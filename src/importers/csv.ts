/** RFC 4180 CSV parsing: quoted fields, escaped quotes and embedded newlines. */

export function parseCsv(text: string, delimiter = ','): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = '';
  let quoted = false;
  const input = text.replace(/^\uFEFF/, '');

  for (let i = 0; i < input.length; i += 1) {
    const char = input[i] as string;
    if (quoted) {
      if (char === '"') {
        if (input[i + 1] === '"') {
          field += '"';
          i += 1;
        } else {
          quoted = false;
        }
      } else {
        field += char;
      }
      continue;
    }
    if (char === '"' && field.length === 0) {
      quoted = true;
    } else if (char === delimiter) {
      row.push(field);
      field = '';
    } else if (char === '\n' || char === '\r') {
      if (char === '\r' && input[i + 1] === '\n') {
        i += 1;
      }
      row.push(field);
      rows.push(row);
      row = [];
      field = '';
    } else {
      field += char;
    }
  }
  if (field.length > 0 || row.length > 0) {
    row.push(field);
    rows.push(row);
  }
  return rows.filter((r) => r.some((cell) => cell.trim() !== ''));
}

/** Picks the delimiter that splits the header line into the most columns. */
export function detectDelimiter(text: string): string {
  const firstLine = text.replace(/^\uFEFF/, '').split(/\r?\n/, 1)[0] ?? '';
  const candidates = [',', ';', '\t'];
  let best = ',';
  let bestCount = 0;
  for (const candidate of candidates) {
    const count = firstLine.split(candidate).length;
    if (count > bestCount) {
      best = candidate;
      bestCount = count;
    }
  }
  return best;
}

/** Parses CSV with a header row into objects keyed by header name. */
export function parseCsvObjects(text: string): Record<string, string>[] {
  const rows = parseCsv(text, detectDelimiter(text));
  const [header, ...body] = rows;
  if (!header) {
    return [];
  }
  const keys = header.map((h) => h.trim());
  return body.map((cells) => {
    const record: Record<string, string> = {};
    keys.forEach((key, index) => {
      record[key] = (cells[index] ?? '').trim();
    });
    return record;
  });
}
