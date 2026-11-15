/**
 * Family 6, file upload handling in code. Verdict: needs_validation.
 *
 *   inside.code_upload_unchecked  the CLIENT'S file name decides where the upload is written (file.originalname,
 *                                 file.name, req.files.x.name reaching path.join / a write / mv / multer's filename
 *                                 callback), or the client's content type (file.mimetype) is stored as the object's
 *                                 type with no allow list anywhere in the file.
 *                                 Python (Flask): file.save(os.path.join(dir, file.filename)) with no secure_filename.
 *                                 PHP: move_uploaded_file to a path built from $_FILES[...]['name'].
 *   inside.code_upload_served     a folder named like uploads served as static files by Express (express.static,
 *                                 serve-static) with nothing that forces a download or blocks type sniffing: an
 *                                 uploaded .html or .svg then opens as a page of the site.
 *
 * GUARDS: a name that went through path.basename, a sanitiser, a slug, a hash or a generated id is not the client's
 * name any more (only the extension taken with path.extname is not flagged: a known miss, the extension is still the
 * client's); a file with a type allow list (fileFilter, includes(mimetype), a switch or a regular expression on the
 * type, file-type / magic-bytes checks) is not flagged for the content type; a static folder with a
 * Content-Disposition or X-Content-Type-Options header set in the same file is not flagged.
 * KNOWN RISKS of a false alarm: an admin-only upload; a bucket that never serves the files back.
 * Languages: JavaScript and TypeScript (multer, express-fileupload, formidable, busboy, Next.js formData); Python
 * (Flask) and PHP in the one form named above.
 */
import type * as TS from "typescript";
import { bare, calleeName, dotted, importsOf, lineOfNode, prop, receiverOf, strLit, taintAt, walk } from "./ast";
import { isPython, pyCalls, pyCode } from "./py";
import { finding, lineOf, shortText, type R2File, type R2Finding, type Ts } from "./types";

const CLIENT_NAME = /^(?:originalname|originalFilename|originalFileName|filename|name)$/;
const FILE_OBJECT = /(?:^|\.)(?:file|files|upload|uploads|uploaded\w*|attachment|image|avatar|photo|doc|document|part)\w*(?:\[[^\]]+\])?$|req\.files?\b|request\.files?\b/i;
const NAME_CLEANERS = /^(?:basename|sanitize\w*|slugify|slug|uuid\w*|v4|randomUUID|randomBytes|nanoid|createHash|hash\w*|encodeURIComponent|secure\w*|safe\w*|clean\w*|normalize\w*|extname|replace|replaceAll)$/i;
const TYPE_ALLOWLIST = /fileFilter|allowedTypes|allowedMime|ALLOWED_|allowed_|whitelist|mimetype\s*(?:===?|!==?)|\.includes\(\s*[\w.]*mimetype|mimetype\)|mimetype\.(?:startsWith|match|test)|\.test\(\s*[\w.]*mimetype|switch\s*\(\s*[\w.]*mimetype|file-type|fileTypeFromBuffer|magic-bytes|mmmagic|image-type|sharp\(/i;
const PATH_SINKS = new Set(["join", "resolve", "writeFile", "writeFileSync", "createWriteStream", "rename", "renameSync", "copyFile", "copyFileSync", "mv", "move", "moveSync", "saveAs", "appendFile"]);

/** Does this expression read the client's own file name (file.originalname, req.files.doc.name)? */
function clientFileName(ts: Ts, sf: TS.SourceFile, e: TS.Expression): boolean {
  const x = bare(ts, e);
  if (ts.isPropertyAccessExpression(x) && CLIENT_NAME.test(x.name.text)) {
    const owner = dotted(ts, ts.isElementAccessExpression(x.expression) ? x.expression.expression : x.expression) ?? x.expression.getText(sf);
    if (x.name.text === "originalname" || x.name.text === "originalFilename" || x.name.text === "originalFileName") return true;
    if (FILE_OBJECT.test(owner) || FILE_OBJECT.test(x.expression.getText(sf))) return true;
    // const f = req.files.doc; ... f.name: one step through the local name
    const o = bare(ts, x.expression);
    const from = ts.isIdentifier(o) ? taintAt(ts, sf, x).originOf(o.text) : undefined;
    return !!from && FILE_OBJECT.test(from.getText(sf));
  }
  if (ts.isTemplateExpression(x)) return x.templateSpans.some((s) => clientFileName(ts, sf, s.expression));
  if (ts.isBinaryExpression(x) && x.operatorToken.kind === ts.SyntaxKind.PlusToken) return clientFileName(ts, sf, x.left) || clientFileName(ts, sf, x.right);
  if (ts.isCallExpression(x)) {
    const name = calleeName(ts, x);
    if (NAME_CLEANERS.test(name)) return false;
    // path.join(dir, file.originalname) nested in another call
    if (name === "join" || name === "resolve" || name === "concat") return x.arguments.some((a) => clientFileName(ts, sf, a));
    return false;
  }
  return false;
}

export function uploadFindings(ts: Ts, f: R2File, sf: TS.SourceFile): R2Finding[] {
  const out: R2Finding[] = [];
  const imp = importsOf(ts, sf);
  const uploadLib = ["multer", "express-fileupload", "formidable", "busboy", "@fastify/multipart", "connect-multiparty", "multiparty", "koa-body", "koa-multer", "@koa/multer"].some((m) => imp.modules.has(m));
  const uploadish = uploadLib || /\bformData\s*\(\s*\)|\.files?\b[\s\S]{0,40}\b(?:originalname|mimetype)\b|originalname/.test(f.content);
  if (!uploadish && !/\bstatic\s*\(/.test(f.content)) return out;
  const hasAllowlist = TYPE_ALLOWLIST.test(f.content);
  const headerSet = /Content-Disposition|X-Content-Type-Options|nosniff|setHeaders|helmet\s*\(/i.test(f.content);
  const lines = new Set<number>();
  const add = (rule: string, n: TS.Node, meta: Record<string, string>) => {
    const line = lineOfNode(sf, n);
    if (lines.has(line)) return;
    lines.add(line);
    out.push(finding(rule, f, line, meta, { snippet: shortText(n.getText(sf)) }));
  };

  walk(ts, sf, (n) => {
    // the content type the client sent, stored as the object's type
    if (uploadish && !hasAllowlist && ts.isPropertyAssignment(n) && (ts.isIdentifier(n.name) || ts.isStringLiteral(n.name)) && /^(?:ContentType|contentType|content_type|mimeType|mime)$/.test(n.name.text)) {
      const v = bare(ts, n.initializer);
      if (ts.isPropertyAccessExpression(v) && /^(?:mimetype|type)$/.test(v.name.text) && FILE_OBJECT.test(v.expression.getText(sf))) add("inside.code_upload_unchecked", n, { what: "the client's content type is stored unchecked", field: v.getText(sf).slice(0, 60) });
      return;
    }
    if (!ts.isCallExpression(n)) return;
    const name = calleeName(ts, n);
    const recv = receiverOf(ts, n);

    // multer.diskStorage({ filename(req, file, cb) { cb(null, file.originalname) } })
    if (uploadish && name === "diskStorage" && n.arguments[0] && ts.isObjectLiteralExpression(n.arguments[0])) {
      const fnProp = n.arguments[0].properties.find((p) => (ts.isPropertyAssignment(p) || ts.isMethodDeclaration(p)) && p.name && ts.isIdentifier(p.name) && p.name.text === "filename");
      if (fnProp) {
        walk(ts, fnProp, (c) => {
          if (ts.isCallExpression(c) && c.arguments.length >= 2 && ts.isIdentifier(c.expression) && /^(?:cb|callback|done|next)$/.test(c.expression.text) && clientFileName(ts, sf, c.arguments[1]!)) add("inside.code_upload_unchecked", c, { what: "the client's file name is the stored name", sink: "multer filename" });
        });
      }
      return;
    }
    // path.join(dir, file.originalname), fs.writeFile(dir + file.name, ...), file.mv(dir + file.name)
    if (uploadish && PATH_SINKS.has(name)) {
      const pathy = /^(?:path|fs|fsp|fse|fsPromises|fs\.promises)$/.test(recv) || name === "mv" || name === "saveAs" || name === "createWriteStream";
      if (pathy && n.arguments.some((a) => clientFileName(ts, sf, a))) {
        // path.join(...) handed straight to a cleaner is not a write
        const parent = n.parent;
        if (parent && ts.isCallExpression(parent) && NAME_CLEANERS.test(calleeName(ts, parent))) return;
        add("inside.code_upload_unchecked", n, { what: "the client's file name decides the stored path", sink: recv ? `${recv}.${name}` : name });
      }
      return;
    }
    // app.use("/uploads", express.static("uploads"))
    if (name === "static" || (ts.isIdentifier(n.expression) && imp.ns.get(n.expression.text) === "serve-static")) {
      const isExpress = /^(?:express|e)$/.test(recv) || imp.ns.get(recv) === "express" || (ts.isIdentifier(n.expression) && imp.ns.get(n.expression.text) === "serve-static");
      if (!isExpress || headerSet) return;
      const dirText = n.arguments[0]?.getText(sf) ?? "";
      const mount = n.parent && ts.isCallExpression(n.parent) && calleeName(ts, n.parent) === "use" ? strLit(ts, n.parent.arguments[0]) ?? "" : "";
      const opts = n.arguments[1];
      if (opts && ts.isObjectLiteralExpression(opts) && prop(ts, opts, "setHeaders")) return;
      if (/upload|user[-_]?files|attachments|user[-_]?content/i.test(dirText) || /upload|attachments|user[-_]?content/i.test(mount)) add("inside.code_upload_served", n, { what: "an uploads folder is served as static files", folder: shortText(dirText, 80) });
    }
  });
  return out;
}

export function textUploadFindings(f: R2File): R2Finding[] {
  const out: R2Finding[] = [];
  if (isPython(f.path)) {
    const code = pyCode(f.content);
    if (!/\brequest\.files\b/.test(code)) return out;
    for (const c of pyCalls(code, "[A-Za-z_]\\w*\\.save")) {
      if (!/\.filename\b/.test(c.args) || /secure_filename\s*\(/.test(c.args)) continue;
      // the name was cleaned on an earlier line of the same function: filename = secure_filename(file.filename)
      const before = code.split("\n").slice(Math.max(0, c.line - 15), c.line).join("\n");
      if (/secure_filename\s*\(|uuid\.uuid4|werkzeug\.utils\.secure_filename/.test(before) && !/\.filename\b/.test(c.first.replace(/secure_filename\s*\([^)]*\)/g, ""))) continue;
      out.push(finding("inside.code_upload_unchecked", f, c.line, { what: "the client's file name decides the stored path", sink: c.name, language: "python" }, { snippet: shortText(f.content.split("\n")[c.line - 1] ?? "") }));
    }
    return out;
  }
  if (/\.php$/i.test(f.path)) {
    for (const m of f.content.matchAll(/\bmove_uploaded_file\s*\(\s*[^,]+,\s*([^;\n]*\$_FILES\s*\[[^\]]+\]\s*\[\s*["']name["']\s*\][^;\n]*)\)/g)) {
      if (/\b(?:basename|pathinfo|uniqid|md5|sha1|hash|bin2hex|preg_replace)\s*\(/.test(m[1]!)) continue;
      const line = lineOf(f.content, m.index!);
      out.push(finding("inside.code_upload_unchecked", f, line, { what: "the client's file name decides the stored path", sink: "move_uploaded_file", language: "php" }, { snippet: shortText(m[0]) }));
    }
  }
  return out;
}
