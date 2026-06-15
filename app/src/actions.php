<?php

declare(strict_types=1);

function show_register(): void
{
    render('회원가입', function (): void {
        ?>
        <section class="panel narrow">
            <p class="eyebrow">Account</p>
            <h1>회원가입</h1>
            <form method="post" action="/register" class="stack">
                <?= csrf_field() ?>
                <label>
                    아이디
                    <input type="text" name="username" required minlength="3" maxlength="30" pattern="[A-Za-z0-9_]+" autocomplete="username">
                </label>
                <label>
                    비밀번호
                    <input type="password" name="password" required minlength="10" autocomplete="new-password">
                </label>
                <label>
                    비밀번호 확인
                    <input type="password" name="password_confirm" required minlength="10" autocomplete="new-password">
                </label>
                <button type="submit">가입하기</button>
            </form>
            <p class="helper">이미 계정이 있으면 <a href="/login">로그인</a>하세요.</p>
        </section>
        <?php
    });
}

function handle_register(): void
{
    enforce_security_rate_limit('register_attempt', ['register', client_ip()], 10, 60 * 60, '회원가입 요청이 너무 많습니다. 잠시 후 다시 시도해 주세요.');
    record_security_event('register_attempt', ['register', client_ip()]);

    $username = trim((string) ($_POST['username'] ?? ''));
    $password = (string) ($_POST['password'] ?? '');
    $confirm = (string) ($_POST['password_confirm'] ?? '');

    if (!preg_match('/^[A-Za-z0-9_]{3,30}$/', $username)) {
        flash('error', '아이디는 영문, 숫자, 밑줄만 사용해 3~30자로 입력해 주세요.');
        redirect('/register');
    }

    if (strlen($password) > MAX_PASSWORD_LENGTH || strlen($confirm) > MAX_PASSWORD_LENGTH) {
        flash('error', '비밀번호는 ' . MAX_PASSWORD_LENGTH . '자 이하로 입력해 주세요.');
        redirect('/register');
    }

    if (!valid_password_strength($password)) {
        flash('error', '비밀번호는 10자 이상이며 영문자와 숫자를 포함해야 합니다.');
        redirect('/register');
    }

    if (!hash_equals($password, $confirm)) {
        flash('error', '비밀번호 확인이 일치하지 않습니다.');
        redirect('/register');
    }

    try {
        $stmt = db()->prepare('INSERT INTO users (username, password) VALUES (?, ?)');
        $stmt->execute([$username, password_hash_value($password)]);
        $user = [
            'id' => (int) db()->lastInsertId(),
            'username' => $username,
        ];
        login_user($user);
        flash('success', '회원가입이 완료되었습니다.');
        redirect('/boards/free/posts');
    } catch (PDOException $exception) {
        if ($exception->getCode() === '23000') {
            flash('error', '회원가입을 처리할 수 없습니다. 입력값을 확인해 주세요.');
            redirect('/register');
        }

        throw $exception;
    }
}

function show_login(): void
{
    render('로그인', function (): void {
        ?>
        <section class="panel narrow">
            <p class="eyebrow">Account</p>
            <h1>로그인</h1>
            <form method="post" action="/login" class="stack">
                <?= csrf_field() ?>
                <label>
                    아이디
                    <input type="text" name="username" required autocomplete="username">
                </label>
                <label>
                    비밀번호
                    <input type="password" name="password" required autocomplete="current-password">
                </label>
                <button type="submit">로그인</button>
            </form>
            <p class="helper">처음 오셨다면 <a href="/register">회원가입</a>을 먼저 해 주세요.</p>
        </section>
        <?php
    });
}

function handle_login(): void
{
    $username = trim((string) ($_POST['username'] ?? ''));
    $password = (string) ($_POST['password'] ?? '');
    $loginIdentity = ['login', client_ip(), strtolower($username)];
    $loginIpIdentity = ['login_ip', client_ip()];

    enforce_security_rate_limit('login_fail', $loginIdentity, 5, 15 * 60, '로그인 실패가 너무 많습니다. 15분 후 다시 시도해 주세요.');
    enforce_security_rate_limit('login_fail_ip', $loginIpIdentity, 30, 15 * 60, '로그인 실패가 너무 많습니다. 15분 후 다시 시도해 주세요.');

    if (strlen($username) > MAX_USERNAME_CHARS * 4 || strlen($password) > MAX_PASSWORD_LENGTH) {
        record_security_event('login_fail', $loginIdentity, $username);
        record_security_event('login_fail_ip', $loginIpIdentity, $username);
        flash('error', '아이디 또는 비밀번호가 올바르지 않습니다.');
        redirect('/login');
    }

    $stmt = db()->prepare('SELECT id, username, password FROM users WHERE username = ?');
    $stmt->execute([$username]);
    $user = $stmt->fetch();
    $hash = $user['password'] ?? '$2y$10$usesomesillystringfore7hnbRJHxXVLeakoG8K30oukPsA.ztMG';

    if (!$user || !password_verify($password, (string) $hash)) {
        record_security_event('login_fail', $loginIdentity, $username);
        record_security_event('login_fail_ip', $loginIpIdentity, $username);
        flash('error', '아이디 또는 비밀번호가 올바르지 않습니다.');
        redirect('/login');
    }

    clear_security_events('login_fail', $loginIdentity);
    clear_security_events('login_fail_ip', $loginIpIdentity);
    if (password_needs_upgrade((string) $hash)) {
        $rehash = db()->prepare('UPDATE users SET password = ? WHERE id = ?');
        $rehash->execute([password_hash_value($password), (int) $user['id']]);
    }
    login_user($user);
    flash('success', '로그인되었습니다.');
    redirect('/boards/free/posts');
}

function handle_logout(): void
{
    logout_user();
    session_start();
    session_regenerate_id(true);
    $now = time();
    $_SESSION['created_at'] = $now;
    $_SESSION['last_activity'] = $now;
    $_SESSION['last_regenerated'] = $now;
    $_SESSION['fingerprint'] = session_fingerprint();
    $_SESSION['_csrf'] = bin2hex(random_bytes(32));
    flash('success', '로그아웃되었습니다.');
    redirect('/login');
}

function list_posts(string $slug): void
{
    $board = board_by_slug($slug);
    $q = trim((string) ($_GET['q'] ?? ''));
    $sort = (string) ($_GET['sort'] ?? 'new');
    $direction = $sort === 'old' ? 'ASC' : 'DESC';
    $sort = $sort === 'old' ? 'old' : 'new';
    $params = [$board['id']];
    $where = ['p.board_id = ?'];

    if ($q !== '') {
        if (text_too_long($q, MAX_SEARCH_CHARS, MAX_SEARCH_CHARS * 4)) {
            abort_request(400, '검색어가 너무 깁니다.');
        }
        enforce_security_rate_limit('post_search', ['post_search', client_ip()], 180, 60 * 60, '게시글 검색 요청이 너무 많습니다. 잠시 후 다시 시도해 주세요.');
        record_security_event('post_search', ['post_search', client_ip()]);
        $where[] = "(p.title LIKE ? ESCAPE '!' OR p.content LIKE ? ESCAPE '!' OR u.username LIKE ? ESCAPE '!')";
        $like = like_pattern($q);
        array_push($params, $like, $like, $like);
    }

    $sql = "
        SELECT
            p.id,
            p.title,
            p.content,
            p.created_at,
            p.updated_at,
            u.username,
            COUNT(DISTINCT c.id) AS comment_count,
            COUNT(DISTINCT a.id) AS attachment_count
        FROM posts p
        INNER JOIN users u ON u.id = p.author_id
        LEFT JOIN comments c ON c.post_id = p.id
        LEFT JOIN attachments a ON a.post_id = p.id
        WHERE " . implode(' AND ', $where) . "
        GROUP BY p.id, p.title, p.content, p.created_at, p.updated_at, u.username
        ORDER BY p.created_at {$direction}, p.id {$direction}
        LIMIT 100
    ";

    $stmt = db()->prepare($sql);
    $stmt->execute($params);
    $posts = $stmt->fetchAll();
    $user = current_user();

    render($board['name'], function () use ($board, $posts, $q, $sort, $user): void {
        ?>
        <section class="board-head">
            <div>
                <p class="eyebrow">Board</p>
                <h1><?= h($board['name']) ?></h1>
                <p><?= h($board['description']) ?></p>
            </div>
            <?php if ($user): ?>
                <a class="button" href="/boards/<?= h($board['slug']) ?>/posts/new">글쓰기</a>
            <?php else: ?>
                <a class="button secondary" href="/login">로그인 후 글쓰기</a>
            <?php endif; ?>
        </section>

        <form method="get" action="/boards/<?= h($board['slug']) ?>/posts" class="toolbar">
            <input type="search" name="q" value="<?= h($q) ?>" placeholder="제목, 본문, 작성자 검색">
            <select name="sort" aria-label="정렬">
                <option value="new" <?= $sort === 'new' ? 'selected' : '' ?>>최신순</option>
                <option value="old" <?= $sort === 'old' ? 'selected' : '' ?>>오래된순</option>
            </select>
            <button type="submit">검색</button>
            <?php if ($q !== ''): ?>
                <a class="button ghost" href="/boards/<?= h($board['slug']) ?>/posts">초기화</a>
            <?php endif; ?>
        </form>

        <section class="post-list">
            <?php if (!$posts): ?>
                <div class="empty">게시글이 없습니다.</div>
            <?php endif; ?>
            <?php foreach ($posts as $post): ?>
                <article class="post-card">
                    <div>
                        <h2><a href="/posts/<?= h((string) $post['id']) ?>"><?= h($post['title']) ?></a></h2>
                        <p><?= h(short_excerpt($post['content'])) ?></p>
                    </div>
                    <div class="meta">
                        <span><?= h($post['username']) ?></span>
                        <span><?= h(format_date($post['created_at'])) ?></span>
                        <span>댓글 <?= h((string) $post['comment_count']) ?></span>
                        <span>파일 <?= h((string) $post['attachment_count']) ?></span>
                    </div>
                </article>
            <?php endforeach; ?>
        </section>
        <?php
    });
}

function show_new_post(string $slug): void
{
    require_login();
    $board = board_by_slug($slug);

    render('글쓰기', function () use ($board): void {
        ?>
        <section class="panel">
            <p class="eyebrow"><?= h($board['name']) ?></p>
            <h1>글쓰기</h1>
            <form method="post" action="/boards/<?= h($board['slug']) ?>/posts" enctype="multipart/form-data" class="stack">
                <?= csrf_field() ?>
                <label>
                    제목
                    <input type="text" name="title" required maxlength="200">
                </label>
                <label>
                    본문
                    <textarea name="content" required rows="12"></textarea>
                </label>
                <label>
                    첨부파일
                    <input type="file" name="attachments[]" multiple>
                </label>
                <p class="helper">허용: pdf, 이미지, txt, zip, docx, xlsx, pptx · 파일당 최대 5MB</p>
                <div class="actions">
                    <button type="submit">등록</button>
                    <a class="button secondary" href="/boards/<?= h($board['slug']) ?>/posts">취소</a>
                </div>
            </form>
        </section>
        <?php
    });
}

function create_post(string $slug): void
{
    $user = require_login();
    $rateIdentity = ['post_create', (int) $user['id'], client_ip()];
    enforce_security_rate_limit('post_create', $rateIdentity, 20, 60 * 60, '게시글 작성이 너무 많습니다. 잠시 후 다시 시도해 주세요.');

    $board = board_by_slug($slug);
    [$title, $content] = validated_post_input();
    $pdo = db();
    $movedPaths = [];

    try {
        $pdo->beginTransaction();
        $stmt = $pdo->prepare('INSERT INTO posts (board_id, title, content, author_id) VALUES (?, ?, ?, ?)');
        $stmt->execute([(int) $board['id'], $title, $content, (int) $user['id']]);
        $postId = (int) $pdo->lastInsertId();
        store_uploaded_files($postId, 'attachments', $movedPaths);
        $pdo->commit();
        record_security_event('post_create', $rateIdentity, (string) $postId);
        flash('success', '게시글이 등록되었습니다.');
        redirect('/posts/' . $postId);
    } catch (Throwable $exception) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        cleanup_paths($movedPaths);
        throw $exception;
    }
}

function show_post(int $id): void
{
    $post = post_by_id($id);
    $comments = comments_for_post($id);
    $attachments = attachments_for_post($id);
    $user = current_user();
    $isAuthor = $user && (int) $user['id'] === (int) $post['author_id'];

    render($post['title'], function () use ($post, $comments, $attachments, $user, $isAuthor): void {
        ?>
        <article class="panel post-detail">
            <div class="detail-head">
                <div>
                    <p class="eyebrow"><a href="/boards/<?= h($post['board_slug']) ?>/posts"><?= h($post['board_name']) ?></a></p>
                    <h1><?= h($post['title']) ?></h1>
                    <p class="meta-line">작성자 <?= h($post['username']) ?> · <?= h(format_date($post['created_at'])) ?></p>
                </div>
                <?php if ($isAuthor): ?>
                    <div class="actions">
                        <a class="button secondary" href="/posts/<?= h((string) $post['id']) ?>/edit">수정</a>
                        <form method="post" action="/posts/<?= h((string) $post['id']) ?>" class="inline-form" data-confirm="게시글을 삭제할까요?">
                            <?= csrf_field() ?>
                            <input type="hidden" name="_method" value="DELETE">
                            <button type="submit" class="danger">삭제</button>
                        </form>
                    </div>
                <?php endif; ?>
            </div>

            <div class="content-body"><?= nl2br(h($post['content'])) ?></div>

            <section class="attachments">
                <h2>첨부파일</h2>
                <?php if (!$attachments): ?>
                    <p class="helper">첨부파일이 없습니다.</p>
                <?php else: ?>
                    <ul class="file-list">
                        <?php foreach ($attachments as $file): ?>
                            <?php $expiresAt = file_download_expires(); ?>
                            <li>
                                <a href="/files/<?= h((string) $file['id']) ?>?exp=<?= h((string) $expiresAt) ?>&amp;t=<?= h(file_download_token($file, $expiresAt)) ?>"><?= h($file['original_name']) ?></a>
                                <span><?= h(format_bytes((int) $file['size_bytes'])) ?></span>
                            </li>
                        <?php endforeach; ?>
                    </ul>
                <?php endif; ?>

                <?php if ($isAuthor): ?>
                    <form method="post" action="/posts/<?= h((string) $post['id']) ?>/files" enctype="multipart/form-data" class="compact-upload">
                        <?= csrf_field() ?>
                        <input type="file" name="attachments[]" multiple required>
                        <button type="submit">파일 추가</button>
                    </form>
                <?php endif; ?>
            </section>
        </article>

        <section class="panel comments">
            <h2>댓글</h2>
            <?php if ($user): ?>
                <form method="post" action="/posts/<?= h((string) $post['id']) ?>/comments" class="stack comment-form">
                    <?= csrf_field() ?>
                    <label>
                        댓글 작성
                        <textarea name="content" required rows="4"></textarea>
                    </label>
                    <button type="submit">댓글 등록</button>
                </form>
            <?php else: ?>
                <p class="helper"><a href="/login">로그인</a>하면 댓글을 작성할 수 있습니다.</p>
            <?php endif; ?>

            <div class="comment-list">
                <?php if (!$comments): ?>
                    <div class="empty">댓글이 없습니다.</div>
                <?php endif; ?>
                <?php foreach ($comments as $comment): ?>
                    <?php $canEditComment = $user && (int) $user['id'] === (int) $comment['author_id']; ?>
                    <article class="comment">
                        <div class="comment-main">
                            <strong><?= h($comment['username']) ?></strong>
                            <span><?= h(format_date($comment['created_at'])) ?></span>
                            <p><?= nl2br(h($comment['content'])) ?></p>
                        </div>
                        <?php if ($canEditComment): ?>
                            <details class="comment-edit">
                                <summary>수정</summary>
                                <form method="post" action="/comments/<?= h((string) $comment['id']) ?>" class="stack">
                                    <?= csrf_field() ?>
                                    <input type="hidden" name="_method" value="PUT">
                                    <textarea name="content" required rows="3"><?= h($comment['content']) ?></textarea>
                                    <button type="submit">저장</button>
                                </form>
                            </details>
                            <form method="post" action="/comments/<?= h((string) $comment['id']) ?>" class="inline-form" data-confirm="댓글을 삭제할까요?">
                                <?= csrf_field() ?>
                                <input type="hidden" name="_method" value="DELETE">
                                <button type="submit" class="link-button danger-text">삭제</button>
                            </form>
                        <?php endif; ?>
                    </article>
                <?php endforeach; ?>
            </div>
        </section>
        <?php
    });
}

function show_edit_post(int $id): void
{
    $user = require_login();
    $post = post_by_id($id);
    ensure_post_author($post, (int) $user['id']);
    $attachments = attachments_for_post($id);

    render('게시글 수정', function () use ($post, $attachments): void {
        ?>
        <section class="panel">
            <p class="eyebrow"><?= h($post['board_name']) ?></p>
            <h1>게시글 수정</h1>
            <form method="post" action="/posts/<?= h((string) $post['id']) ?>" enctype="multipart/form-data" class="stack">
                <?= csrf_field() ?>
                <input type="hidden" name="_method" value="PUT">
                <label>
                    제목
                    <input type="text" name="title" value="<?= h($post['title']) ?>" required maxlength="200">
                </label>
                <label>
                    본문
                    <textarea name="content" required rows="12"><?= h($post['content']) ?></textarea>
                </label>

                <fieldset>
                    <legend>기존 첨부파일</legend>
                    <?php if (!$attachments): ?>
                        <p class="helper">첨부파일이 없습니다.</p>
                    <?php endif; ?>
                    <?php foreach ($attachments as $file): ?>
                        <label class="check-row">
                            <input type="checkbox" name="delete_attachments[]" value="<?= h((string) $file['id']) ?>">
                            삭제: <?= h($file['original_name']) ?> (<?= h(format_bytes((int) $file['size_bytes'])) ?>)
                        </label>
                    <?php endforeach; ?>
                </fieldset>

                <label>
                    새 첨부파일 추가
                    <input type="file" name="attachments[]" multiple>
                </label>
                <div class="actions">
                    <button type="submit">수정 저장</button>
                    <a class="button secondary" href="/posts/<?= h((string) $post['id']) ?>">취소</a>
                </div>
            </form>
        </section>
        <?php
    });
}

function update_post(int $id): void
{
    $user = require_login();
    $rateIdentity = ['post_update', (int) $user['id'], client_ip()];
    enforce_security_rate_limit('post_update', $rateIdentity, 60, 60 * 60, '게시글 수정이 너무 많습니다. 잠시 후 다시 시도해 주세요.');

    $post = post_by_id($id);
    ensure_post_author($post, (int) $user['id']);
    [$title, $content] = validated_post_input();
    $deleteIds = array_values(array_filter(array_map('intval', (array) ($_POST['delete_attachments'] ?? []))));
    $pdo = db();
    $movedPaths = [];
    $filesToDelete = [];

    try {
        $pdo->beginTransaction();
        lock_post_for_update($id);
        $stmt = $pdo->prepare('UPDATE posts SET title = ?, content = ? WHERE id = ?');
        $stmt->execute([$title, $content, $id]);

        if ($deleteIds) {
            $placeholders = implode(',', array_fill(0, count($deleteIds), '?'));
            $select = $pdo->prepare("SELECT * FROM attachments WHERE post_id = ? AND id IN ({$placeholders})");
            $select->execute(array_merge([$id], $deleteIds));
            $filesToDelete = $select->fetchAll();

            if ($filesToDelete) {
                $delete = $pdo->prepare("DELETE FROM attachments WHERE post_id = ? AND id IN ({$placeholders})");
                $delete->execute(array_merge([$id], array_column($filesToDelete, 'id')));
            }
        }

        store_uploaded_files($id, 'attachments', $movedPaths);
        $pdo->commit();

        foreach ($filesToDelete as $file) {
            delete_attachment_file($file);
        }

        flash('success', '게시글이 수정되었습니다.');
        record_security_event('post_update', $rateIdentity, (string) $id);
        redirect('/posts/' . $id);
    } catch (Throwable $exception) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        cleanup_paths($movedPaths);
        throw $exception;
    }
}

function delete_post(int $id): void
{
    $user = require_login();
    $post = post_by_id($id);
    ensure_post_author($post, (int) $user['id']);
    $pdo = db();

    try {
        $pdo->beginTransaction();
        lock_post_for_update($id);
        $files = attachments_for_post($id);
        $stmt = $pdo->prepare('DELETE FROM posts WHERE id = ?');
        $stmt->execute([$id]);
        $pdo->commit();
    } catch (Throwable $exception) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        throw $exception;
    }

    foreach ($files as $file) {
        delete_attachment_file($file);
    }

    flash('success', '게시글이 삭제되었습니다.');
    redirect('/boards/' . $post['board_slug'] . '/posts');
}

function add_comment(int $postId): void
{
    $user = require_login();
    $rateIdentity = ['comment_create', (int) $user['id'], client_ip()];
    enforce_security_rate_limit('comment_create', $rateIdentity, 60, 60 * 60, '댓글 작성이 너무 많습니다. 잠시 후 다시 시도해 주세요.');

    post_by_id($postId);
    $content = trim((string) ($_POST['content'] ?? ''));

    if ($content === '' || text_too_long($content, MAX_BODY_CHARS, MAX_BODY_BYTES)) {
        flash('error', '댓글 내용을 입력해 주세요.');
        redirect('/posts/' . $postId);
    }

    $stmt = db()->prepare('INSERT INTO comments (post_id, author_id, content) VALUES (?, ?, ?)');
    $stmt->execute([$postId, (int) $user['id'], $content]);
    record_security_event('comment_create', $rateIdentity, (string) $postId);
    flash('success', '댓글이 등록되었습니다.');
    redirect('/posts/' . $postId);
}

function update_comment(int $id): void
{
    $user = require_login();
    $comment = comment_by_id($id);
    ensure_comment_author($comment, (int) $user['id']);
    $content = trim((string) ($_POST['content'] ?? ''));

    if ($content === '' || text_too_long($content, MAX_BODY_CHARS, MAX_BODY_BYTES)) {
        flash('error', '댓글 내용을 입력해 주세요.');
        redirect('/posts/' . $comment['post_id']);
    }

    $stmt = db()->prepare('UPDATE comments SET content = ? WHERE id = ?');
    $stmt->execute([$content, $id]);
    flash('success', '댓글이 수정되었습니다.');
    redirect('/posts/' . $comment['post_id']);
}

function delete_comment(int $id): void
{
    $user = require_login();
    $comment = comment_by_id($id);
    ensure_comment_author($comment, (int) $user['id']);
    $stmt = db()->prepare('DELETE FROM comments WHERE id = ?');
    $stmt->execute([$id]);
    flash('success', '댓글이 삭제되었습니다.');
    redirect('/posts/' . $comment['post_id']);
}

function upload_files_to_post(int $postId): void
{
    $user = require_login();
    $rateIdentity = ['file_upload', (int) $user['id'], client_ip()];
    enforce_security_rate_limit('file_upload', $rateIdentity, 30, 60 * 60, '파일 업로드가 너무 많습니다. 잠시 후 다시 시도해 주세요.');

    $post = post_by_id($postId);
    ensure_post_author($post, (int) $user['id']);
    $movedPaths = [];

    try {
        db()->beginTransaction();
        lock_post_for_update($postId);
        $count = store_uploaded_files($postId, 'attachments', $movedPaths);
        db()->commit();
    } catch (Throwable $exception) {
        if (db()->inTransaction()) {
            db()->rollBack();
        }
        cleanup_paths($movedPaths);
        throw $exception;
    }

    if ($count > 0) {
        record_security_event('file_upload', $rateIdentity, (string) $postId);
    }
    flash($count > 0 ? 'success' : 'error', $count > 0 ? '파일이 추가되었습니다.' : '업로드할 파일을 선택해 주세요.');
    redirect('/posts/' . $postId);
}

function download_file(int $id): void
{
    $expiresAt = filter_input(INPUT_GET, 'exp', FILTER_VALIDATE_INT);
    $token = (string) ($_GET['t'] ?? '');
    if (!is_int($expiresAt) || $expiresAt < time() || $expiresAt > time() + FILE_DOWNLOAD_TOKEN_TTL_SECONDS + 60) {
        abort_request(403, '파일 다운로드 링크가 만료되었습니다. 게시글을 새로고침해 주세요.');
    }

    $stmt = db()->prepare('SELECT * FROM attachments WHERE id = ?');
    $stmt->execute([$id]);
    $file = $stmt->fetch();

    $expectedToken = is_array($file) ? file_download_token($file, $expiresAt) : str_repeat('0', 64);
    $tokenOk = $token !== '' && hash_equals($expectedToken, $token);

    if (!is_array($file) || !$tokenOk) {
        abort_request(403, '파일 다운로드 권한을 확인할 수 없습니다.');
    }

    $path = safe_upload_path((string) $file['stored_path']);
    if (!is_file($path)) {
        abort_request(404, '저장된 파일이 없습니다.');
    }

    $downloadName = clean_download_name((string) $file['original_name']);
    $fallback = preg_replace('/[^A-Za-z0-9._-]/', '_', $downloadName) ?: 'download';

    header('Content-Type: application/octet-stream');
    header('X-Content-Type-Options: nosniff');
    header('Content-Length: ' . filesize($path));
    header('Cache-Control: private, no-store, max-age=0');
    header(
        'Content-Disposition: attachment; filename="' . $fallback . '"; filename*=UTF-8\'\'' . rawurlencode($downloadName)
    );
    readfile($path);
    exit;
}

function list_users(): void
{
    enforce_security_rate_limit('user_search', ['user_search', client_ip()], 120, 60 * 60, '유저 검색 요청이 너무 많습니다. 잠시 후 다시 시도해 주세요.');
    record_security_event('user_search', ['user_search', client_ip()]);

    $q = trim((string) ($_GET['q'] ?? ''));
    $params = [];
    $where = '';
    $users = [];
    $error = '';

    if ($q !== '') {
        if (text_len($q) < 2) {
            $error = '검색어는 2자 이상 입력해 주세요.';
        } elseif (text_too_long($q, 50, 200)) {
            $error = '검색어가 너무 깁니다.';
        }
        $where = "WHERE u.username LIKE ? ESCAPE '!'";
        $params[] = like_pattern($q);
    }

    if ($q !== '' && $error === '') {
        $stmt = db()->prepare("
            SELECT
                u.id,
                u.username,
                u.created_at,
                COUNT(DISTINCT p.id) AS post_count,
                COUNT(DISTINCT c.id) AS comment_count
            FROM users u
            LEFT JOIN posts p ON p.author_id = u.id
            LEFT JOIN comments c ON c.author_id = u.id
            {$where}
            GROUP BY u.id, u.username, u.created_at
            ORDER BY u.username ASC
            LIMIT 50
        ");
        $stmt->execute($params);
        $users = $stmt->fetchAll();
    }

    render('유저 검색', function () use ($users, $q, $error): void {
        ?>
        <section class="panel">
            <p class="eyebrow">Users</p>
            <h1>유저 검색</h1>
            <form method="get" action="/users" class="toolbar">
                <input type="search" name="q" value="<?= h($q) ?>" placeholder="아이디 검색">
                <button type="submit">검색</button>
                <?php if ($q !== ''): ?>
                    <a class="button ghost" href="/users">초기화</a>
                <?php endif; ?>
            </form>
            <?php if ($error !== ''): ?>
                <div class="alert alert-warning" role="alert"><?= h($error) ?></div>
            <?php elseif ($q === ''): ?>
                <p class="helper">검색어를 2자 이상 입력하면 유저를 찾을 수 있습니다.</p>
            <?php endif; ?>
            <div class="table-wrap">
                <table>
                    <thead>
                        <tr>
                            <th>아이디</th>
                            <th>가입일</th>
                            <th>작성 글</th>
                            <th>작성 댓글</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if (!$users): ?>
                            <tr><td colspan="4">검색 결과가 없습니다.</td></tr>
                        <?php endif; ?>
                        <?php foreach ($users as $user): ?>
                            <tr>
                                <td><?= h($user['username']) ?></td>
                                <td><?= h(format_date($user['created_at'])) ?></td>
                                <td><?= h((string) $user['post_count']) ?></td>
                                <td><?= h((string) $user['comment_count']) ?></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </section>
        <?php
    });
}

function post_by_id(int $id): array
{
    $stmt = db()->prepare('
        SELECT
            p.*,
            b.slug AS board_slug,
            b.name AS board_name,
            u.username
        FROM posts p
        INNER JOIN boards b ON b.id = p.board_id
        INNER JOIN users u ON u.id = p.author_id
        WHERE p.id = ?
    ');
    $stmt->execute([$id]);
    $post = $stmt->fetch();

    if (!$post) {
        abort_request(404, '게시글을 찾을 수 없습니다.');
    }

    return $post;
}

function comments_for_post(int $postId): array
{
    $stmt = db()->prepare('
        SELECT c.*, u.username
        FROM comments c
        INNER JOIN users u ON u.id = c.author_id
        WHERE c.post_id = ?
        ORDER BY c.created_at ASC, c.id ASC
    ');
    $stmt->execute([$postId]);
    return $stmt->fetchAll();
}

function comment_by_id(int $id): array
{
    $stmt = db()->prepare('SELECT * FROM comments WHERE id = ?');
    $stmt->execute([$id]);
    $comment = $stmt->fetch();

    if (!$comment) {
        abort_request(404, '댓글을 찾을 수 없습니다.');
    }

    return $comment;
}

function attachments_for_post(int $postId): array
{
    $stmt = db()->prepare('SELECT * FROM attachments WHERE post_id = ? ORDER BY id ASC');
    $stmt->execute([$postId]);
    return $stmt->fetchAll();
}

function attachment_usage_for_post(int $postId): array
{
    $stmt = db()->prepare('SELECT COUNT(*) AS file_count, COALESCE(SUM(size_bytes), 0) AS total_bytes FROM attachments WHERE post_id = ?');
    $stmt->execute([$postId]);
    $usage = $stmt->fetch();

    return [
        'file_count' => (int) ($usage['file_count'] ?? 0),
        'total_bytes' => (int) ($usage['total_bytes'] ?? 0),
    ];
}

function enforce_attachment_quota(int $postId, int $incomingCount, int $incomingBytes): void
{
    if ($incomingCount === 0) {
        return;
    }

    $usage = attachment_usage_for_post($postId);
    if ($usage['file_count'] + $incomingCount > MAX_ATTACHMENTS_PER_POST) {
        abort_request(400, '게시글 하나에 첨부할 수 있는 파일 개수를 초과했습니다.');
    }

    if ($usage['total_bytes'] + $incomingBytes > MAX_ATTACHMENT_BYTES_PER_POST) {
        abort_request(400, '게시글 하나에 첨부할 수 있는 총 파일 용량을 초과했습니다.');
    }
}

function ensure_post_author(array $post, int $userId): void
{
    if ((int) $post['author_id'] !== $userId) {
        abort_request(403, '작성자만 수정하거나 삭제할 수 있습니다.');
    }
}

function ensure_comment_author(array $comment, int $userId): void
{
    if ((int) $comment['author_id'] !== $userId) {
        abort_request(403, '댓글 작성자만 수정하거나 삭제할 수 있습니다.');
    }
}

function valid_password_strength(string $password): bool
{
    if (strlen($password) < MIN_PASSWORD_LENGTH) {
        return false;
    }

    return preg_match('/[A-Za-z]/', $password) === 1 && preg_match('/[0-9]/', $password) === 1;
}

function validated_post_input(): array
{
    $title = trim((string) ($_POST['title'] ?? ''));
    $content = trim((string) ($_POST['content'] ?? ''));

    if ($title === '' || text_too_long($title, MAX_TITLE_CHARS, MAX_TITLE_CHARS * 4)) {
        flash('error', '제목은 1~200자 범위로 입력해 주세요.');
        redirect(route_path());
    }

    if ($content === '' || text_too_long($content, MAX_BODY_CHARS, MAX_BODY_BYTES)) {
        flash('error', '본문은 1~20000자 범위로 입력해 주세요.');
        redirect(route_path());
    }

    return [$title, $content];
}

function short_excerpt(string $value): string
{
    $plain = trim(preg_replace('/\s+/', ' ', $value) ?? '');
    if (function_exists('mb_strlen') && function_exists('mb_substr')) {
        return mb_strlen($plain, 'UTF-8') > 120 ? mb_substr($plain, 0, 120, 'UTF-8') . '...' : $plain;
    }

    return strlen($plain) > 240 ? substr($plain, 0, 240) . '...' : $plain;
}

function allowed_upload_types(): array
{
    return [
        'pdf' => ['application/pdf'],
        'png' => ['image/png'],
        'jpg' => ['image/jpeg'],
        'jpeg' => ['image/jpeg'],
        'gif' => ['image/gif'],
        'txt' => ['text/plain'],
        'zip' => ['application/zip', 'application/x-zip-compressed'],
        'docx' => ['application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'application/zip'],
        'xlsx' => ['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'application/zip'],
        'pptx' => ['application/vnd.openxmlformats-officedocument.presentationml.presentation', 'application/zip'],
    ];
}

function normalize_files(string $field): array
{
    if (empty($_FILES[$field])) {
        return [];
    }

    $raw = $_FILES[$field];
    if (!is_array($raw) || !array_key_exists('name', $raw)) {
        abort_request(400, '파일 업로드 요청 형식이 올바르지 않습니다.');
    }

    if (!is_array($raw['name'])) {
        if (!is_string($raw['name'] ?? '') || !is_string($raw['tmp_name'] ?? '')) {
            abort_request(400, '파일 업로드 요청 형식이 올바르지 않습니다.');
        }
        return [$raw];
    }

    $files = [];
    foreach ($raw['name'] as $index => $name) {
        if (!is_string($name) || !is_string($raw['tmp_name'][$index] ?? '')) {
            abort_request(400, '파일 업로드 요청 형식이 올바르지 않습니다.');
        }
        $files[] = [
            'name' => $name,
            'type' => $raw['type'][$index] ?? '',
            'tmp_name' => $raw['tmp_name'][$index] ?? '',
            'error' => $raw['error'][$index] ?? UPLOAD_ERR_NO_FILE,
            'size' => $raw['size'][$index] ?? 0,
        ];
    }

    return $files;
}

function store_uploaded_files(int $postId, string $field, array &$movedPaths): int
{
    $files = normalize_files($field);
    $allowed = allowed_upload_types();
    $count = 0;
    $finfo = new finfo(FILEINFO_MIME_TYPE);
    $stmt = db()->prepare('
        INSERT INTO attachments (post_id, original_name, stored_path, mime_type, size_bytes)
        VALUES (?, ?, ?, ?, ?)
    ');
    $uploadFiles = [];
    $incomingBytes = 0;

    foreach ($files as $file) {
        $error = (int) ($file['error'] ?? UPLOAD_ERR_NO_FILE);
        if ($error === UPLOAD_ERR_NO_FILE) {
            continue;
        }
        if ($error !== UPLOAD_ERR_OK) {
            abort_request(400, '파일 업로드 중 오류가 발생했습니다.');
        }

        $size = (int) ($file['size'] ?? 0);
        if ($size <= 0 || $size > MAX_UPLOAD_BYTES) {
            abort_request(400, '파일은 1바이트 이상, 5MB 이하만 업로드할 수 있습니다.');
        }

        $uploadFiles[] = $file;
        $incomingBytes += $size;
    }

    if (count($uploadFiles) > MAX_UPLOAD_FILES_PER_REQUEST) {
        abort_request(400, '한 번에 업로드할 수 있는 파일 개수를 초과했습니다.');
    }

    lock_post_for_update($postId);
    enforce_attachment_quota($postId, count($uploadFiles), $incomingBytes);

    foreach ($uploadFiles as $file) {
        $size = (int) ($file['size'] ?? 0);
        $originalName = clean_download_name((string) ($file['name'] ?? ''));
        if (text_too_long($originalName, MAX_UPLOAD_NAME_CHARS, 255)) {
            abort_request(400, '파일명이 너무 깁니다.');
        }
        $extension = strtolower(pathinfo($originalName, PATHINFO_EXTENSION));
        if (!isset($allowed[$extension])) {
            abort_request(400, '허용되지 않는 파일 형식입니다.');
        }

        $tmpName = (string) ($file['tmp_name'] ?? '');
        if (!is_uploaded_file($tmpName)) {
            abort_request(400, '업로드 파일을 확인할 수 없습니다.');
        }

        $mime = $finfo->file($tmpName) ?: 'application/octet-stream';
        if (!in_array($mime, $allowed[$extension], true)) {
            abort_request(400, '파일 내용과 확장자가 일치하지 않습니다.');
        }
        if (in_array($extension, ['docx', 'xlsx', 'pptx'], true) && !valid_ooxml_file($tmpName, $extension)) {
            abort_request(400, 'Office 문서 구조가 올바르지 않습니다.');
        }

        $storedName = bin2hex(random_bytes(16)) . '.' . $extension;
        $targetPath = UPLOAD_DIR . DIRECTORY_SEPARATOR . $storedName;
        if (!move_uploaded_file($tmpName, $targetPath)) {
            abort_request(500, '파일을 저장하지 못했습니다.');
        }
        chmod($targetPath, 0644);
        $movedPaths[] = $targetPath;

        $stmt->execute([$postId, $originalName, $storedName, $mime, $size]);
        $count++;
    }

    return $count;
}

function lock_post_for_update(int $postId): void
{
    if (!db()->inTransaction()) {
        return;
    }

    $stmt = db()->prepare('SELECT id FROM posts WHERE id = ? FOR UPDATE');
    $stmt->execute([$postId]);
    if (!$stmt->fetch()) {
        abort_request(404, '게시글을 찾을 수 없습니다.');
    }
}

function valid_ooxml_file(string $path, string $extension): bool
{
    if (!class_exists(ZipArchive::class)) {
        return false;
    }

    $requiredPrefix = match ($extension) {
        'docx' => 'word/',
        'xlsx' => 'xl/',
        'pptx' => 'ppt/',
        default => null,
    };
    if ($requiredPrefix === null) {
        return false;
    }

    $zip = new ZipArchive();
    if ($zip->open($path) !== true) {
        return false;
    }

    $hasContentTypes = $zip->locateName('[Content_Types].xml') !== false;
    $hasRequiredPart = false;
    $entryLimit = min($zip->numFiles, 2000);

    for ($i = 0; $i < $entryLimit; $i++) {
        $name = $zip->getNameIndex($i);
        if (is_string($name) && str_starts_with($name, $requiredPrefix)) {
            $hasRequiredPart = true;
            break;
        }
    }

    $zip->close();

    return $hasContentTypes && $hasRequiredPart;
}

function clean_download_name(string $name): string
{
    $name = str_replace('\\', '/', $name);
    $name = basename($name);
    $name = preg_replace('/[\x00-\x1F\x7F"]/u', '_', $name) ?? '';
    $name = trim($name, " .");

    return $name !== '' ? $name : 'download';
}

function safe_upload_path(string $storedPath): string
{
    $base = realpath(UPLOAD_DIR);
    if ($base === false) {
        abort_request(500, '업로드 디렉터리를 찾을 수 없습니다.');
    }

    $path = $base . DIRECTORY_SEPARATOR . basename($storedPath);
    $real = realpath($path);
    if ($real === false || !str_starts_with($real, $base . DIRECTORY_SEPARATOR)) {
        abort_request(404, '파일을 찾을 수 없습니다.');
    }

    return $real;
}

function delete_attachment_file(array $file): void
{
    try {
        $path = safe_upload_path((string) $file['stored_path']);
        if (is_file($path)) {
            unlink($path);
        }
    } catch (Throwable) {
    }
}

function cleanup_paths(array $paths): void
{
    foreach ($paths as $path) {
        if (is_file($path)) {
            @unlink($path);
        }
    }
}
