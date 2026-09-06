<?php
/**
 * Joomla 5/6 hosting scanner: malware, permissions, processes, report.
 * Change JSCAN_KEY before upload. Delete this file after use.
 *
 * Usage: /jscan.php?key=YOUR_KEY
 */
declare(strict_types=1);

const JSCAN_KEY = 'change-this-key';
const JSCAN_TIME_BUDGET = 18.0;
const JSCAN_SCAN_BATCH = 280;
const JSCAN_CHMOD_BATCH = 450;
const JSCAN_HTACCESS_BATCH = 80;

if (!isset($_GET['key']) || !hash_equals(JSCAN_KEY, (string) $_GET['key'])) {
    header('HTTP/1.1 403 Forbidden');
    exit('Forbidden');
}

@set_time_limit(90);
@ini_set('max_execution_time', '90');
@ini_set('memory_limit', '256M');
ignore_user_abort(true);

header('X-Robots-Tag: noindex, nofollow');
header('Cache-Control: no-store');

$ROOT = str_replace('\\', '/', __DIR__);
$TMP = $ROOT . '/tmp';
$STATE_FILE = $TMP . '/jscan-state.json';
$REPORT_JSON = $TMP . '/jscan-report.json';
$REPORT_HTML = $TMP . '/jscan-report.html';
$QUAR = $TMP . '/jscan-quarantine';
$SELF = basename(__FILE__);
$DEADLINE = microtime(true) + JSCAN_TIME_BUDGET;

$SKIP_FRAG = [
    '/libraries/vendor/',
    '/media/vendor/',
    '/plugins/system/helixultimate/vendor/',
    '/administrator/components/com_sppagebuilder/assets/editor/dist/',
    '/tmp/jscan-quarantine/',
    '/tmp/jscan-state.json',
    '/tmp/jscan-report.',
];

$HOT_DIRS = ['/images/', '/tmp/', '/cache/', '/media/', '/files/', '/cgi-bin/'];
$ENTRY = [
    '/index.php',
    '/administrator/index.php',
    '/api/index.php',
    '/configuration.php',
    '/includes/app.php',
    '/includes/framework.php',
    '/cli/joomla.php',
];

$SIG_HIGH = '/UPLOADER_OK|Gagal rename|com_jce renamed|FilesMan|c99shell|r57shell|WSO\s*2|b374k|FilesTools/i';
$SIG_EVAL = '/eval\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13|gzdecode)\s*\(/i';
$SIG_UPLOAD = '/move_uploaded_file\s*\([^;]*__DIR__\s*\.\s*[\'"]\/\.\./i';
$SIG_PREPEND = '/auto_prepend_file|auto_append_file/i';
$SIG_SHELL = '/(?:shell_exec|passthru|system|exec|popen|proc_open)\s*\(\s*\$(?:_GET|_POST|_REQUEST|_COOKIE)/i';

$PROC_BAD = '/cli\/cf|layouts\/cf|xmrig|kinsing|kdevtmpfsi|\.\/cf\b|\/dev\/shm\/|wget\s+http|curl\s+http.*\|?\s*bash/i';
$PROC_KEEP = '/\b(php|httpd|apache|mysqld|mariadbd|nginx|litespeed|lsphp|cron|sshd)\b/i';

$MAL_EXT = ['php', 'php3', 'php4', 'php5', 'php7', 'php8', 'php9', 'pht', 'phtml', 'phar', 'phps', 'shtml', 'shtm', 'cgi', 'pl', 'py', 'asp', 'aspx', 'sh'];

function jscan_h(string $s): string
{
    return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function jscan_rel(string $root, string $path): string
{
    $path = str_replace('\\', '/', $path);
    if (stripos($path, $root) === 0) {
        return substr($path, strlen($root)) ?: '/';
    }
    return $path;
}

function jscan_skip_content(string $rel, array $skip): bool
{
    foreach ($skip as $frag) {
        if (stripos($rel, $frag) !== false) {
            return true;
        }
    }
    return false;
}

function jscan_in_hot(string $rel, array $hot): bool
{
    if ($rel === '') {
        return false;
    }
    $r = $rel[0] === '/' ? $rel : '/' . $rel;
    if ($r === '/tmp' || str_starts_with($r, '/tmp/')) {
        if (str_starts_with($r, '/tmp/jscan-')) {
            return false;
        }
    }
    foreach ($hot as $d) {
        if (str_starts_with($r, $d) || $r === rtrim($d, '/')) {
            return true;
        }
    }
    return false;
}

function jscan_mkdir(string $dir): bool
{
    if (is_dir($dir)) {
        return true;
    }
    return @mkdir($dir, 0755, true);
}

function jscan_load_state(string $file): array
{
    if (!is_file($file)) {
        return [];
    }
    $raw = @file_get_contents($file);
    $data = json_decode((string) $raw, true);
    return is_array($data) ? $data : [];
}

function jscan_save_state(string $file, array $state): void
{
    jscan_mkdir(dirname($file));
    @file_put_contents($file, json_encode($state, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
}

function jscan_url(array $q): string
{
    $q['key'] = JSCAN_KEY;
    return basename(__FILE__) . '?' . http_build_query($q);
}

function jscan_redirect(array $q): void
{
    header('Location: ' . jscan_url($q));
    exit;
}

function jscan_page_start(string $title): void
{
    header('Content-Type: text/html; charset=utf-8');
    echo '<!DOCTYPE html><html lang="ru"><head><meta charset="utf-8"><title>' . jscan_h($title) . '</title>';
    echo '<style>
body{font:15px/1.45 system-ui,Segoe UI,sans-serif;margin:20px;max-width:980px;background:#111;color:#eee}
a{color:#8cf} h1,h2{color:#fff} h2{border-bottom:1px solid #444;padding-bottom:6px}
.btn{display:inline-block;background:#1a6;color:#fff;padding:10px 16px;border-radius:8px;text-decoration:none;margin:6px 8px 6px 0}
.btn2{background:#444}
.btn3{background:#a33}
pre,textarea{white-space:pre-wrap;word-break:break-all;background:#1c1c1c;padding:10px;border-radius:8px;width:100%;box-sizing:border-box}
.ok{color:#8f8}.bad{color:#f88}.warn{color:#fc6}
table{border-collapse:collapse;width:100%;font-size:13px} td,th{border:1px solid #444;padding:5px 7px;text-align:left;vertical-align:top}
</style></head><body>';
}

function jscan_page_end(): void
{
    echo '</body></html>';
}

function jscan_run(string $cmd): array
{
    $buf = [];
    $rc = -1;
    if (!function_exists('exec')) {
        return ['rc' => -1, 'out' => 'exec недоступен'];
    }
    $disabled = array_map('trim', explode(',', (string) ini_get('disable_functions')));
    if (in_array('exec', $disabled, true)) {
        return ['rc' => -1, 'out' => 'exec запрещён'];
    }
    @exec($cmd . ' 2>&1', $buf, $rc);
    return ['rc' => (int) $rc, 'out' => implode("\n", $buf)];
}

function jscan_version(string $root): string
{
    $f = $root . '/libraries/src/Version.php';
    if (!is_file($f)) {
        return 'unknown';
    }
    $c = (string) @file_get_contents($f);
    if (preg_match("/MAJOR_VERSION\s*=\s*(\d+)/", $c, $m)) {
        return $m[1];
    }
    return 'unknown';
}

function jscan_head_tail(string $path, int $limit = 65536): string
{
    $size = @filesize($path);
    if ($size === false || $size < 1) {
        return '';
    }
    if ($size <= $limit) {
        return (string) @file_get_contents($path);
    }
    $h = (string) @file_get_contents($path, false, null, 0, intdiv($limit, 2));
    $t = (string) @file_get_contents($path, false, null, max(0, $size - intdiv($limit, 2)), intdiv($limit, 2));
    return $h . "\n" . $t;
}

function jscan_snippet(string $buf, int $len = 220): string
{
    $buf = preg_replace('/\s+/', ' ', $buf) ?? $buf;
    if (function_exists('mb_substr')) {
        return mb_substr($buf, 0, $len);
    }
    return substr($buf, 0, $len);
}

function jscan_collect_paths(string $root, array $skipContent, string $self): array
{
    $scan = [];
    $chmod = [];
    $nestedHt = [];
    $it = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::SELF_FIRST,
        RecursiveIteratorIterator::CATCH_GET_CHILD
    );
    foreach ($it as $item) {
        $path = str_replace('\\', '/', $item->getPathname());
        $rel = jscan_rel($root, $path);
        if ($item->isDir()) {
            $chmod[] = $rel;
            continue;
        }
        $name = $item->getFilename();
        if ($name === $self) {
            continue;
        }
        $chmod[] = $rel;
        $isHt = strcasecmp($name, '.htaccess') === 0;
        if ($isHt && jscan_is_nested_htaccess($rel)) {
            $nestedHt[] = $rel;
        }
        if ($isHt || !jscan_skip_content($rel, $skipContent)) {
            $scan[] = $rel;
        }
    }
    return ['scan' => $scan, 'chmod' => $chmod, 'nested_htaccess' => $nestedHt];
}

function jscan_is_nested_htaccess(string $rel): bool
{
    if (strcasecmp(basename($rel), '.htaccess') !== 0) {
        return false;
    }
    if ($rel === '/.htaccess') {
        return false;
    }
    if (stripos($rel, '/tmp/jscan-') !== false) {
        return false;
    }
    return true;
}

function jscan_is_protected(string $rel, array $entry): bool
{
    if (in_array($rel, $entry, true) || $rel === '/.htaccess' || $rel === '/configuration.php') {
        return true;
    }
    if (preg_match('#^/templates/[^/]+/index\.php$#', $rel)) {
        return true;
    }
    if (str_starts_with($rel, '/libraries/src/') || str_starts_with($rel, '/administrator/includes/')) {
        return true;
    }
    return false;
}

function jscan_htaccess_is_hack(string $buf): bool
{
    if ($buf === '') {
        return false;
    }
    $allowBackdoors = preg_match('/adminfuns\.php|chtmlfuns\.php|cjfuns\.php|classsmtps\.php|comdofuns\.php|epinyins\.php|gdftps\.php|hplfuns\.php|onclickfuns\.php|phpzipincs\.php|schallfuns\.php|siteheads\.php|termps\.php|txets\.php|thoms\.php|copypaths\.php|delpaths\.php/i', $buf);
    $caseSoup = preg_match('/FilesMatch[^>\n]{0,400}(?:pHP7|PHP7|Php\|PHp|php5\|suspected|suspected\)\$)/i', $buf)
        || preg_match('/FilesMatch[^\n]+suspected/i', $buf);
    $denyThenWpAllow = preg_match('/FilesMatch/i', $buf)
        && preg_match('/Deny from all/i', $buf)
        && preg_match('/Allow from all/i', $buf)
        && preg_match('/wp-login\.php|wp-blog-header\.php|wp-trackback\.php/i', $buf);
    return (bool) ($allowBackdoors || $caseSoup || $denyThenWpAllow);
}

function jscan_default_htaccess(string $root): string
{
    $joomlaTxt = $root . '/htaccess.txt';
    if (is_file($joomlaTxt)) {
        $txt = (string) @file_get_contents($joomlaTxt);
        if ($txt !== '' && !jscan_htaccess_is_hack($txt)) {
            return $txt;
        }
    }
    if (is_file($root . '/wp-config.php') && !is_file($root . '/configuration.php')) {
        return "# Restored by jscan (WordPress default)\n<IfModule mod_rewrite.c>\nRewriteEngine On\nRewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]\nRewriteBase /\nRewriteRule ^index\\.php$ - [L]\nRewriteCond %{REQUEST_FILENAME} !-f\nRewriteCond %{REQUEST_FILENAME} !-d\nRewriteRule . /index.php [L]\n</IfModule>\n";
    }
    return "# Restored by jscan (Joomla minimal)\nOptions -Indexes\n<IfModule mod_rewrite.c>\nRewriteEngine On\nRewriteBase /\nRewriteRule ^index\\.php$ - [L]\nRewriteCond %{REQUEST_FILENAME} !-f\nRewriteCond %{REQUEST_FILENAME} !-d\nRewriteRule . index.php [L]\n</IfModule>\n";
}

function jscan_restore_htaccess(string $root, string $quar, string $rel): array
{
    $src = $root . $rel;
    if (!is_file($src)) {
        return ['ok' => false, 'error' => 'нет файла'];
    }
    $dest = $quar . $rel;
    if (!jscan_mkdir(dirname($dest))) {
        return ['ok' => false, 'error' => 'карантин не создан'];
    }
    if (!@copy($src, $dest)) {
        return ['ok' => false, 'error' => 'копия в карантин не удалась'];
    }
    @file_put_contents($dest . '.reason.txt', "malware htaccess\n");
    $body = jscan_default_htaccess($root);
    if (@file_put_contents($src, $body) === false) {
        return ['ok' => false, 'error' => 'запись нового .htaccess не удалась, оригинал в карантине'];
    }
    @chmod($src, 0644);
    return ['ok' => true, 'error' => ''];
}

function jscan_inspect(string $root, string $rel, array $ctx): ?array
{
    $path = $root . $rel;
    if (!is_file($path)) {
        return null;
    }
    $name = basename($rel);
    $ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));
    $size = (int) @filesize($path);
    $issue = null;
    $reason = '';
    $high = false;
    $buf = '';

    if (preg_match('/^up_\d+\.(pht|shtml|shtm|php[0-9]?|phtml|phar)$/i', $name)) {
        $issue = 'bad_name';
        $reason = 'типичный аплоадер up_NNNN';
        $high = true;
    }
    if (preg_match('/^(shell|c99|c100|r57|wso|bypass|alfa|radio\.php|wp-login|xmlrpc)\.(php|pht|phtml)$/i', $name)) {
        if (stripos($rel, '/plugins/fields/radio/') === false
            && stripos($rel, '/form/field/radio.php') === false
            && stripos($rel, '/plg_osmap') === false
            && stripos($rel, '/plugins/osmap/') === false) {
            $issue = 'bad_name';
            $reason = 'типичное имя шелла';
            $high = true;
        }
    }
    $base = strtolower($name);
    if (($base === 'cf' || $base === 'rt') && (str_contains($rel, '/cli/') || str_contains($rel, '/layouts/'))) {
        $issue = 'bad_name';
        $reason = 'вредонос cf/rt в cli или layouts';
        $high = true;
    }
    if (preg_match('/\.(php[0-9]?|pht|phtml|phar)\.(jpg|jpeg|png|gif|ico|txt|pdf)$/i', $name)
        || preg_match('/\.(jpg|jpeg|png|gif|ico|txt|pdf)\.(php[0-9]?|pht|phtml|phar)$/i', $name)) {
        $issue = 'bad_name';
        $reason = 'двойное расширение';
        $high = true;
    }
    if (preg_match('/^(adminfuns|chtmlfuns|cjfuns|classsmtps|classfuns|comfunctions|comdofuns|copypaths|delpaths|doiconvs|epinyins|filefuns|gdftps|hinfofuns|hplfuns|memberfuns|moddofuns|onclickfuns|phpzipincs|qfunctions|qinfofuns|schallfuns|tempfuns|userfuns|siteheads|termps|txets|thoms|postnews)\.php$/i', $name)
        || ($rel === '/inputs.php' || $rel === '/system_log.php')) {
        $issue = 'bad_name';
        $reason = 'типичное имя бэкдора из взломанного .htaccess';
        $high = true;
    }

    $needContent = in_array($ext, array_merge($ctx['mal_ext'], ['htaccess', 'ini', 'user.ini', 'json', 'txt', 'html', 'htm', 'inc']), true)
        || $name === '.htaccess' || $name === '.user.ini' || $name === 'php.ini';
    if ($needContent && $size > 0 && $size < 8 * 1048576) {
        $buf = jscan_head_tail($path);
    }

    if ($buf !== '') {
        if (preg_match($ctx['sig_high'], $buf) || preg_match($ctx['sig_upload'], $buf)) {
            $issue = 'malware_sig';
            $reason = 'сигнатура бэкдора/аплоадера';
            $high = true;
        } elseif (preg_match($ctx['sig_eval'], $buf) && !str_contains($rel, '/scssphp/')) {
            $issue = $issue ?: 'eval';
            $reason = $reason ?: 'eval(base64/gzinflate)';
        } elseif (preg_match($ctx['sig_shell'], $buf)) {
            $issue = $issue ?: 'shell_user';
            $reason = $reason ?: 'исполнение из GET/POST';
        }
    }

    $hot = jscan_in_hot($rel, $ctx['hot']);
    if ($hot && in_array($ext, $ctx['mal_ext'], true)
        && !in_array(strtolower($name), ['index.html', 'index.htm', '.htaccess'], true)
        && stripos($rel, '/administrator/cache/') === false
        && !(str_starts_with($rel, '/cache/') && $ext === 'php' && $buf !== '' && (str_contains($buf, 'Access Denied') || str_contains($buf, '_JEXEC')))
    ) {
        if (in_array($ext, ['pht', 'shtml', 'shtm', 'phar', 'phps', 'cgi', 'pl', 'py', 'asp', 'aspx', 'sh'], true)
            || str_starts_with($rel, '/images/')
            || str_starts_with($rel, '/tmp/')
            || str_starts_with($rel, '/cache/')
            || str_starts_with($rel, '/cgi-bin/')) {
            $issue = $issue ?: 'hotdir_script';
            $reason = $reason ?: 'скрипт в upload/tmp/images';
            $high = true;
        } elseif (str_starts_with($rel, '/media/') || str_starts_with($rel, '/files/')) {
            $issue = $issue ?: 'hotdir_script';
            $reason = $reason ?: 'скрипт в media/files';
        }
    }

    if (in_array($name, ['.htaccess', '.user.ini', 'php.ini'], true) || $ext === 'ini') {
        if ($buf !== '' && jscan_htaccess_is_hack($buf)) {
            $issue = 'htaccess';
            $reason = 'взломанный .htaccess: запрет PHP + белый список wp/бэкдоров';
            $high = true;
        } elseif ($buf !== '' && preg_match('/auto_prepend_file|auto_append_file|AddHandler\s+application\/x-httpd-php|SetHandler\s+application\/x-httpd-php/i', $buf)) {
            if (!($rel === '/.htaccess' && preg_match('/Joomla/i', $buf) && !preg_match('/auto_prepend_file/i', $buf))) {
                $issue = $issue ?: 'htaccess';
                $reason = $reason ?: 'опасные директивы prepend/handler';
            }
        }
        if ($rel === '/.user.ini' && $buf !== '' && preg_match('/auto_prepend_file\s*=\s*(?!none\b)(?!\s*$).+/i', $buf)) {
            $issue = 'userini';
            $reason = 'auto_prepend указывает на файл';
            $high = true;
        }
        if (jscan_is_nested_htaccess($rel)) {
            $issue = 'htaccess';
            $reason = ($buf !== '' && jscan_htaccess_is_hack($buf))
                ? 'вложенный взломанный .htaccess'
                : 'вложенный .htaccess';
            $high = true;
        }
    }

    if ($ext === 'json' && $buf !== '' && preg_match('/<\?(php|=)|eval\s*\(/i', $buf)) {
        $issue = $issue ?: 'json';
        $reason = $reason ?: 'PHP внутри JSON';
    }

    $isEntry = in_array($rel, $ctx['entry'], true) || preg_match('#^/templates/[^/]+/index\.php$#', $rel);
    if ($isEntry && $buf !== '') {
        if (preg_match($ctx['sig_eval'], $buf) || preg_match($ctx['sig_high'], $buf) || preg_match($ctx['sig_upload'], $buf)) {
            $issue = 'injection';
            $reason = 'вставка во входном файле Joomla';
        } elseif ($rel !== '/configuration.php' && preg_match('/^<\?(php)?\s*(?!\/\*|\/\/\s*NOTE|\/\/\s*@)/', ltrim($buf)) && preg_match('/eval\s*\(|gzinflate|base64_decode\s*\(\s*[\'"][A-Za-z0-9\/+]{40,}/', $buf)) {
            $issue = 'injection';
            $reason = 'обфускация в точке входа';
        }
    }

    if ($issue === null) {
        return null;
    }

    return [
        'path' => $rel,
        'issue' => $issue,
        'reason' => $reason,
        'high' => $high,
        'size' => $size,
        'snippet' => jscan_snippet($buf !== '' ? $buf : $reason),
        'restore_htaccess' => ($name === '.htaccess' && $high && $issue === 'htaccess' && $rel === '/.htaccess'),
    ];
}

function jscan_quarantine_delete(string $root, string $quar, string $rel, string $reason): array
{
    $src = $root . $rel;
    if (!is_file($src) && !is_link($src)) {
        return ['ok' => false, 'error' => 'нет файла'];
    }
    $dest = $quar . $rel;
    if (!jscan_mkdir(dirname($dest))) {
        return ['ok' => false, 'error' => 'карантин не создан'];
    }
    if (!@copy($src, $dest) && !is_link($src)) {
        return ['ok' => false, 'error' => 'копия в карантин не удалась'];
    }
    @file_put_contents($dest . '.reason.txt', $reason . "\n");
    if (!@unlink($src)) {
        return ['ok' => false, 'error' => 'удаление не удалось, карантин есть'];
    }
    return ['ok' => true, 'error' => ''];
}

function jscan_ensure_tmp_htaccess(string $tmp): void
{
    $ht = $tmp . '/.htaccess';
    if (!is_file($ht)) {
        @file_put_contents($ht, "Require all denied\n");
    }
    $qht = $tmp . '/jscan-quarantine/.htaccess';
    jscan_mkdir(dirname($qht));
    if (!is_file($qht)) {
        @file_put_contents($qht, "<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n");
    }
}

function jscan_kill_proc(int $pid): string
{
    if ($pid <= 1) {
        return 'skip';
    }
    if (function_exists('posix_kill') && @posix_kill($pid, 9)) {
        return 'ok';
    }
    $r = jscan_run('kill -9 ' . $pid);
    if ($r['rc'] === 0) {
        return 'ok';
    }
    if (stripos($r['out'], 'Permission denied') !== false || stripos($r['out'], 'not permitted') !== false) {
        return 'denied';
    }
    return 'denied';
}

function jscan_build_reports(string $root, array $state, string $jsonPath, string $htmlPath): void
{
    $actions = $state['actions'] ?? [];
    $findings = $state['findings'] ?? [];
    $procs = $state['processes'] ?? [];
    $deleted = [];
    $restoredHt = false;
    foreach ($actions as $a) {
        $t = $a['type'] ?? '';
        if ($t === 'deleted' || $t === 'restored') {
            $deleted[$a['path'] ?? ''] = true;
        }
        if ($t === 'restored' && ($a['path'] ?? '') === '/.htaccess') {
            $restoredHt = true;
        }
    }
    $needs = [];
    foreach ($findings as $f) {
        $p = $f['path'] ?? '';
        if (isset($deleted[$p])) {
            continue;
        }
        $needs[] = [
            'path' => $p,
            'issue' => $f['issue'] ?? '',
            'snippet' => $f['snippet'] ?? '',
        ];
    }
    $deniedPids = [];
    foreach ($procs as $p) {
        if (($p['kill'] ?? '') === 'denied') {
            $deniedPids[] = (string) $p['pid'];
        }
    }
    $next = [];
    $next[] = 'Скачайте JSON-рапорт и удалите jscan.php с хостинга.';
    if ($deniedPids) {
        $next[] = 'Напишите в поддержку хостинга: завершить PID ' . implode(', ', $deniedPids) . ' (PHP kill запрещён).';
    }
    if ($restoredHt) {
        $next[] = 'Корневой .htaccess восстановлен из htaccess.txt (или минимальных правил). Проверьте свои HTTPS/редиректы — кастомные правила из взломанного файла не переносились.';
    }
    if ($needs) {
        $next[] = 'Локально откройте копию сайта и JSON: правьте только пути из needs_ai_fix.';
    }
    if (empty($actions) && empty($findings)) {
        $next[] = 'Очевидных вредоносов не найдено. Смените пароли админки и MySQL.';
    }
    $next[] = 'Cron в панели хостинга PHP не читает — проверьте задания вручную.';
    $next[] = 'Не оставляйте jscan.php на сайте.';

    $report = [
        'site' => (string) (($_SERVER['HTTP_HOST'] ?? '') !== '' ? $_SERVER['HTTP_HOST'] : $root),
        'root' => $root,
        'joomla_hint' => $state['joomla_hint'] ?? 'unknown',
        'started' => $state['started'] ?? '',
        'finished' => date('c'),
        'loadavg' => $state['loadavg'] ?? '',
        'actions_done' => $actions,
        'findings' => $findings,
        'needs_ai_fix' => $needs,
        'processes' => $procs,
        'next_steps' => $next,
        'chmod' => $state['chmod_stats'] ?? null,
    ];
    @file_put_contents($jsonPath, json_encode($report, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT));

    ob_start();
    echo '<h1>Рапорт jscan</h1>';
    echo '<p>Корень: ' . jscan_h($root) . '<br>Joomla: ' . jscan_h((string) $report['joomla_hint']) . '<br>Load: ' . jscan_h((string) $report['loadavg']) . '</p>';
    $failed = [];
    $done = [];
    foreach ($actions as $a) {
        if (($a['type'] ?? '') === 'failed') {
            $failed[] = $a;
        } else {
            $done[] = $a;
        }
    }
    echo '<h2>Сделано</h2>';
    if (!$done) {
        echo '<p class="ok">Автоудалений не было (или нечего было удалять).</p>';
    } else {
        echo '<table><tr><th>Действие</th><th>Путь</th><th>Почему</th></tr>';
        foreach ($done as $a) {
            echo '<tr><td>' . jscan_h($a['type'] ?? '') . '</td><td>' . jscan_h($a['path'] ?? '') . '</td><td>' . jscan_h($a['reason'] ?? '') . '</td></tr>';
        }
        echo '</table>';
    }
    echo '<h2>Не удалось</h2>';
    if (!$failed) {
        echo '<p class="ok">Ошибок карантина/удаления нет.</p>';
    } else {
        echo '<table><tr><th>Путь</th><th>Почему</th></tr>';
        foreach ($failed as $a) {
            echo '<tr class="bad"><td>' . jscan_h($a['path'] ?? '') . '</td><td>' . jscan_h($a['reason'] ?? '') . '</td></tr>';
        }
        echo '</table>';
    }
    echo '<h2>Нужна правка ИИ / вручную</h2>';
    if (!$needs) {
        echo '<p class="ok">Спорных заражённых файлов ядра нет.</p>';
    } else {
        echo '<table><tr><th>Путь</th><th>Тип</th><th>Фрагмент</th></tr>';
        foreach ($needs as $n) {
            echo '<tr class="warn"><td>' . jscan_h($n['path']) . '</td><td>' . jscan_h($n['issue']) . '</td><td><pre>' . jscan_h($n['snippet']) . '</pre></td></tr>';
        }
        echo '</table>';
    }
    echo '<h2>Процессы</h2>';
    if (!$procs) {
        echo '<p>Вредоносных процессов по шаблонам не видно.</p>';
    } else {
        echo '<table><tr><th>PID</th><th>kill</th><th>Команда</th></tr>';
        foreach ($procs as $p) {
            $cls = ($p['kill'] ?? '') === 'ok' ? 'ok' : 'bad';
            echo '<tr class="' . $cls . '"><td>' . jscan_h((string) $p['pid']) . '</td><td>' . jscan_h($p['kill'] ?? '') . '</td><td><pre>' . jscan_h($p['cmd'] ?? '') . '</pre></td></tr>';
        }
        echo '</table>';
    }
    if ($deniedPids) {
        echo '<h2>Тикет хостеру</h2><textarea rows="8">Прошу завершить процессы пользователя (PHP kill: Permission denied / errno 13).
PID: ' . jscan_h(implode(' ', $deniedPids)) . '
Команды см. в рапорте jscan (cli/cf, layouts/cf или аналоги).
Файлы на диске уже обработаны сканером.
</textarea>';
    }
    echo '<h2>Дальше</h2><ol>';
    foreach ($next as $s) {
        echo '<li>' . jscan_h($s) . '</li>';
    }
    echo '</ol>';
    echo '<h2>JSON для ИИ</h2><textarea rows="18">' . jscan_h((string) file_get_contents($jsonPath)) . '</textarea>';
    $html = ob_get_clean();
    @file_put_contents($htmlPath, '<!DOCTYPE html><html lang="ru"><head><meta charset="utf-8"><title>jscan report</title></head><body>' . $html . '</body></html>');
    $state['_html_body'] = $html;
    $GLOBALS['_jscan_last_html'] = $html;
}

jscan_ensure_tmp_htaccess($TMP);
jscan_mkdir($QUAR);

if (isset($_GET['selfdelete']) && $_GET['selfdelete'] === '1') {
    @unlink($STATE_FILE);
    header('Content-Type: text/plain; charset=utf-8');
    echo @unlink(__FILE__) ? "jscan.php удалён.\n" : "Не удалось удалить jscan.php, уберите файл вручную.\n";
    exit;
}

if (isset($_GET['download']) && $_GET['download'] === 'json' && is_file($REPORT_JSON)) {
    header('Content-Type: application/json; charset=utf-8');
    header('Content-Disposition: attachment; filename="jscan-report.json"');
    readfile($REPORT_JSON);
    exit;
}

$go = isset($_GET['go']) && $_GET['go'] === '1';
$step = (int) ($_GET['step'] ?? 0);
$state = jscan_load_state($STATE_FILE);

if ($step === 4 && $state === [] && is_file($REPORT_JSON)) {
    jscan_page_start('jscan рапорт');
    $prev = (string) @file_get_contents($REPORT_HTML);
    if ($prev !== '' && preg_match('/<body>(.*)<\/body>/s', $prev, $mm)) {
        echo $mm[1];
    } else {
        echo '<h1>Рапорт</h1><p><a class="btn" href="' . jscan_h(jscan_url(['download' => 'json'])) . '">Скачать JSON</a></p>';
        echo '<textarea rows="20">' . jscan_h((string) file_get_contents($REPORT_JSON)) . '</textarea>';
    }
    echo '<p><a class="btn" href="' . jscan_h(jscan_url(['download' => 'json'])) . '">Скачать JSON</a> ';
    echo '<a class="btn btn3" href="' . jscan_h(jscan_url(['selfdelete' => '1'])) . '" onclick="return confirm(\'Удалить jscan.php с сервера?\');">Удалить jscan.php</a></p>';
    jscan_page_end();
    exit;
}

if (!$go) {
    jscan_page_start('jscan — сканер Joomla 5/6');
    echo '<h1>Сканер вредоносов Joomla 5 и 6</h1>';
    echo '<p>Один файл для хостинга. Ядро и расширения <b>не переписываются вслепую</b>. Удаляются только очевидные бэкдоры (аплоадеры <code>up_*.pht</code>, <code>UPLOADER_OK</code>, <code>cf</code> в cli/layouts). Остальное — в рапорт для ИИ.</p>';
    echo '<h2>Как пользоваться</h2><ol>';
    echo '<li><b>Ключ.</b> В <code>jscan.php</code> строка <code>const JSCAN_KEY = \'...\'</code> — это пароль сканера. Он должен совпадать с тем, что после <code>?key=</code> в адресе. Если видите эту страницу — ключ уже верный.</li>';
    echo '<li>Файл должен лежать в корне Joomla (рядом с <code>configuration.php</code>).</li>';
    echo '<li>Нажмите «Полный цикл». Страница сама идёт по шагам: процессы → скан файлов → карантин и права 0755/0644 → рапорт. Вкладку не закрывайте.</li>';
    echo '<li>Скачайте JSON. Если есть <code>needs_ai_fix</code> — отдайте JSON локальному ИИ вместе с копией сайта.</li>';
    echo '<li>Если процессы <code>cli/cf</code> не убились — скопируйте из рапорта текст тикета хостеру.</li>';
    echo '<li><b>Удалите jscan.php</b> кнопкой в конце рапорта или вручную по FTP. Не оставляйте сканер на сайте.</li>';
    echo '</ol>';
    echo '<p class="warn">Не передавайте ссылку с ключом посторонним. Полная инструкция: файл <code>jscan-instrukciya.html</code> на компьютере (на хостинг его заливать не нужно).</p>';
    echo '<p>Ключ в URL проверен. Joomla (по Version.php): <b>' . jscan_h(jscan_version($ROOT)) . '</b></p>';
    echo '<a class="btn" href="' . jscan_h(jscan_url(['go' => '1', 'step' => '1'])) . '">Полный цикл</a>';
    jscan_page_end();
    exit;
}

if ($step <= 1) {
    $state = [
        'started' => date('c'),
        'joomla_hint' => jscan_version($ROOT),
        'step' => 1,
        'scan_paths' => [],
        'chmod_paths' => [],
        'scan_i' => 0,
        'chmod_i' => 0,
        'findings' => [],
        'actions' => [],
        'processes' => [],
        'loadavg' => '',
        'chmod_stats' => ['dirs' => 0, 'files' => 0, 'fail' => 0],
        'nested_htaccess' => [],
        'nested_ht_i' => 0,
        'nested_ht_done' => false,
        'list_done' => false,
        'scan_done' => false,
        'clean_core_done' => false,
        'clean_done' => false,
        'chmod_done' => false,
    ];
} elseif (empty($state['started'])) {
    jscan_redirect(['go' => '1', 'step' => '1']);
}

if ($step <= 1) {
    $load = is_readable('/proc/loadavg') ? trim((string) file_get_contents('/proc/loadavg')) : '';
    if ($load === '' && function_exists('sys_getloadavg')) {
        $load = implode(' ', array_map(static fn($n) => (string) round((float) $n, 2), sys_getloadavg()));
    }
    $state['loadavg'] = $load;
    $ps = jscan_run('ps auxww');
    $lines = preg_split('/\R/', $ps['out']) ?: [];
    $found = [];
    foreach ($lines as $line) {
        if ($line === '' || stripos($line, $SELF) !== false) {
            continue;
        }
        if (!preg_match($PROC_BAD, $line)) {
            continue;
        }
        if (preg_match($PROC_KEEP, $line) && !preg_match('/cli\/cf|layouts\/cf|xmrig|kinsing/', $line)) {
            continue;
        }
        if (!preg_match('/^\S+\s+(\d+)/', $line, $m)) {
            continue;
        }
        $pid = (int) $m[1];
        $kill = jscan_kill_proc($pid);
        $found[] = ['pid' => $pid, 'cmd' => $line, 'kill' => $kill];
    }
    $state['processes'] = $found;
    $state['step'] = 2;
    jscan_save_state($STATE_FILE, $state);
    jscan_page_start('jscan шаг 1');
    echo '<h1>Шаг 1/4 — процессы</h1>';
    echo '<p>loadavg: ' . jscan_h($load) . '</p>';
    echo '<p>Подозрительных процессов: ' . count($found) . '</p>';
    echo '<meta http-equiv="refresh" content="1;url=' . jscan_h(jscan_url(['go' => '1', 'step' => '2'])) . '">';
    echo '<p><a class="btn" href="' . jscan_h(jscan_url(['go' => '1', 'step' => '2'])) . '">Дальше: скан файлов</a></p>';
    jscan_page_end();
    exit;
}

if ($step === 2) {
    if (empty($state['list_done'])) {
        $lists = jscan_collect_paths($ROOT, $SKIP_FRAG, $SELF);
        $state['scan_paths'] = $lists['scan'];
        $state['chmod_paths'] = $lists['chmod'];
        $state['nested_htaccess'] = $lists['nested_htaccess'];
        $state['nested_ht_i'] = 0;
        $state['nested_ht_done'] = false;
        $state['list_done'] = true;
        $state['scan_i'] = 0;
        jscan_save_state($STATE_FILE, $state);
        jscan_page_start('jscan шаг 2');
        echo '<h1>Шаг 2/4 — список файлов</h1>';
        echo '<p>К скану: ' . count($lists['scan']) . ', вложенных .htaccess: ' . count($lists['nested_htaccess']) . ', к chmod: ' . count($lists['chmod']) . '</p>';
        echo '<meta http-equiv="refresh" content="1;url=' . jscan_h(jscan_url(['go' => '1', 'step' => '2'])) . '">';
        echo '<p>Продолжаю скан…</p>';
        jscan_page_end();
        exit;
    }
    $ctx = [
        'mal_ext' => $MAL_EXT,
        'hot' => $HOT_DIRS,
        'entry' => $ENTRY,
        'sig_high' => $SIG_HIGH,
        'sig_eval' => $SIG_EVAL,
        'sig_upload' => $SIG_UPLOAD,
        'sig_shell' => $SIG_SHELL,
    ];
    $paths = $state['scan_paths'];
    $n = count($paths);
    $i = (int) $state['scan_i'];
    $batch = 0;
    while ($i < $n && $batch < JSCAN_SCAN_BATCH && microtime(true) < $DEADLINE) {
        $rel = $paths[$i];
        $hit = jscan_inspect($ROOT, $rel, $ctx);
        if ($hit) {
            $state['findings'][] = $hit;
        }
        $i++;
        $batch++;
    }
    $state['scan_i'] = $i;
    if ($i >= $n) {
        $state['scan_done'] = true;
        $state['step'] = 3;
    }
    jscan_save_state($STATE_FILE, $state);
    jscan_page_start('jscan шаг 2');
    echo '<h1>Шаг 2/4 — скан файлов</h1>';
    echo '<p>' . $i . ' / ' . $n . ' проверено, находок: ' . count($state['findings']) . '</p>';
    if (empty($state['scan_done'])) {
        echo '<meta http-equiv="refresh" content="1;url=' . jscan_h(jscan_url(['go' => '1', 'step' => '2'])) . '">';
        echo '<p>Идёт глубокий рекурсивный обход…</p>';
    } else {
        echo '<meta http-equiv="refresh" content="1;url=' . jscan_h(jscan_url(['go' => '1', 'step' => '3'])) . '">';
        echo '<p><a class="btn" href="' . jscan_h(jscan_url(['go' => '1', 'step' => '3'])) . '">Дальше: чистка и права</a></p>';
    }
    jscan_page_end();
    exit;
}

if ($step === 3) {
    if (empty($state['clean_core_done'])) {
        $ini = $ROOT . '/.user.ini';
        $iniBody = is_file($ini) ? (string) file_get_contents($ini) : '';
        if ($iniBody !== '' && preg_match('/auto_prepend_file\s*=\s*[^\r\n]+/i', $iniBody, $mm)
            && !preg_match('/auto_prepend_file\s*=\s*none/i', $mm[0])) {
            if (preg_match('/auto_prepend_file\s*=\s*[\'"]?([^\'"\s]+)/i', $iniBody, $pm)) {
                $pre = $pm[1];
                if ($pre !== 'none' && $pre !== '') {
                    $prePath = $pre[0] === '/' ? $pre : $ROOT . '/' . ltrim(str_replace('\\', '/', $pre), '/');
                    $preRel = jscan_rel($ROOT, $prePath);
                    if (is_file($prePath) && !in_array($preRel, $ENTRY, true)) {
                        $q = jscan_quarantine_delete($ROOT, $QUAR, $preRel, 'auto_prepend payload');
                        $state['actions'][] = [
                            'type' => $q['ok'] ? 'deleted' : 'quarantine',
                            'path' => $preRel,
                            'reason' => 'auto_prepend: ' . ($q['error'] ?: 'ok'),
                        ];
                    }
                }
            }
            $newIni = preg_replace('/auto_prepend_file\s*=\s*[^\r\n]+/i', 'auto_prepend_file = none', $iniBody) ?? $iniBody;
            $newIni = preg_replace('/auto_append_file\s*=\s*[^\r\n]+/i', 'auto_append_file = none', $newIni) ?? $newIni;
            @file_put_contents($ini, $newIni);
            $state['actions'][] = ['type' => 'userini', 'path' => '/.user.ini', 'reason' => 'prepend/append = none'];
        } elseif (!is_file($ini)) {
            @file_put_contents($ini, "; jscan\nauto_prepend_file = none\nauto_append_file = none\n");
            $state['actions'][] = ['type' => 'userini', 'path' => '/.user.ini', 'reason' => 'создан с prepend none'];
        }

        foreach ($state['findings'] as $f) {
            if (!empty($f['restore_htaccess']) && ($f['path'] ?? '') === '/.htaccess') {
                $q = jscan_restore_htaccess($ROOT, $QUAR, '/.htaccess');
                $state['actions'][] = [
                    'type' => $q['ok'] ? 'restored' : 'failed',
                    'path' => '/.htaccess',
                    'reason' => 'взломанный .htaccess заменён на штатный' . ($q['error'] ? ' (' . $q['error'] . ')' : ' (карантин + htaccess.txt)'),
                ];
            }
        }

        foreach ($state['findings'] as $f) {
            if (empty($f['high'])) {
                continue;
            }
            $rel = $f['path'];
            if (!empty($f['restore_htaccess'])) {
                continue;
            }
            if (jscan_is_nested_htaccess($rel)) {
                continue;
            }
            if (jscan_is_protected($rel, $ENTRY)) {
                continue;
            }
            $q = jscan_quarantine_delete($ROOT, $QUAR, $rel, $f['reason']);
            $state['actions'][] = [
                'type' => $q['ok'] ? 'deleted' : 'failed',
                'path' => $rel,
                'reason' => $f['reason'] . ($q['error'] ? ' (' . $q['error'] . ')' : ''),
            ];
        }
        $state['clean_core_done'] = true;
        jscan_save_state($STATE_FILE, $state);
        jscan_page_start('jscan шаг 3');
        echo '<h1>Шаг 3/4 — карантин</h1>';
        echo '<p>Действий: ' . count($state['actions']) . '. Дальше вложенные .htaccess.</p>';
        echo '<meta http-equiv="refresh" content="1;url=' . jscan_h(jscan_url(['go' => '1', 'step' => '3'])) . '">';
        jscan_page_end();
        exit;
    }

    if (empty($state['nested_ht_done'])) {
        $htList = $state['nested_htaccess'] ?? [];
        $hn = count($htList);
        $hi = (int) ($state['nested_ht_i'] ?? 0);
        $batch = 0;
        while ($hi < $hn && $batch < JSCAN_HTACCESS_BATCH && microtime(true) < $DEADLINE) {
            $rel = $htList[$hi];
            if (jscan_is_nested_htaccess($rel) && is_file($ROOT . $rel)) {
                $q = jscan_quarantine_delete($ROOT, $QUAR, $rel, 'вложенный .htaccess');
                $state['actions'][] = [
                    'type' => $q['ok'] ? 'deleted' : 'failed',
                    'path' => $rel,
                    'reason' => 'вложенный .htaccess' . ($q['error'] ? ' (' . $q['error'] . ')' : ''),
                ];
            }
            $hi++;
            $batch++;
        }
        $state['nested_ht_i'] = $hi;
        if ($hi >= $hn) {
            $state['nested_ht_done'] = true;
            $state['clean_done'] = true;
            jscan_ensure_tmp_htaccess($TMP);
        }
        jscan_save_state($STATE_FILE, $state);
        jscan_page_start('jscan шаг 3');
        echo '<h1>Шаг 3/4 — вложенные .htaccess</h1>';
        echo '<p>' . $hi . ' / ' . $hn . ' удалено в карантин.</p>';
        echo '<meta http-equiv="refresh" content="1;url=' . jscan_h(jscan_url(['go' => '1', 'step' => '3'])) . '">';
        jscan_page_end();
        exit;
    }

    $paths = $state['chmod_paths'];
    $n = count($paths);
    $i = (int) $state['chmod_i'];
    $stats = $state['chmod_stats'];
    $batch = 0;
    while ($i < $n && $batch < JSCAN_CHMOD_BATCH && microtime(true) < $DEADLINE) {
        $rel = $paths[$i];
        $full = $ROOT . $rel;
        if (is_dir($full)) {
            if (@chmod($full, 0755)) {
                $stats['dirs']++;
            } else {
                $stats['fail']++;
            }
        } elseif (is_file($full)) {
            if (@chmod($full, 0644)) {
                $stats['files']++;
            } else {
                $stats['fail']++;
            }
        }
        $i++;
        $batch++;
    }
    $state['chmod_i'] = $i;
    $state['chmod_stats'] = $stats;
    if ($i >= $n) {
        @chmod($ROOT, 0755);
        @chmod($ROOT . '/configuration.php', 0644);
        @chmod(__FILE__, 0644);
        $state['chmod_done'] = true;
        $state['step'] = 4;
        $state['actions'][] = [
            'type' => 'chmod',
            'path' => '/',
            'reason' => 'dirs 0755 files 0644 d=' . $stats['dirs'] . ' f=' . $stats['files'] . ' fail=' . $stats['fail'],
        ];
    }
    jscan_save_state($STATE_FILE, $state);
    jscan_page_start('jscan шаг 3');
    echo '<h1>Шаг 3/4 — права</h1>';
    echo '<p>' . $i . ' / ' . $n . ' (папок ' . (int) $stats['dirs'] . ', файлов ' . (int) $stats['files'] . ')</p>';
    if (empty($state['chmod_done'])) {
        echo '<meta http-equiv="refresh" content="1;url=' . jscan_h(jscan_url(['go' => '1', 'step' => '3'])) . '">';
    } else {
        echo '<meta http-equiv="refresh" content="1;url=' . jscan_h(jscan_url(['go' => '1', 'step' => '4'])) . '">';
        echo '<p><a class="btn" href="' . jscan_h(jscan_url(['go' => '1', 'step' => '4'])) . '">Дальше: рапорт</a></p>';
    }
    jscan_page_end();
    exit;
}

jscan_build_reports($ROOT, $state, $REPORT_JSON, $REPORT_HTML);
@unlink($STATE_FILE);

jscan_page_start('jscan рапорт');
echo $GLOBALS['_jscan_last_html'] ?? '<p>Рапорт записан.</p>';
echo '<p><a class="btn" href="' . jscan_h(jscan_url(['download' => 'json'])) . '">Скачать JSON</a>';
echo '<a class="btn btn3" href="' . jscan_h(jscan_url(['selfdelete' => '1'])) . '" onclick="return confirm(\'Удалить jscan.php с сервера?\');">Удалить jscan.php</a></p>';
jscan_page_end();
