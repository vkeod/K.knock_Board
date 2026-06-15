<?php

declare(strict_types=1);

require_once dirname(__DIR__) . '/src/bootstrap.php';
require_once dirname(__DIR__) . '/src/actions.php';

try {
    $path = route_path();
    $method = effective_method();

    if (in_array($method, ['POST', 'PUT', 'DELETE'], true)) {
        verify_same_origin();
        verify_csrf();
    }

    if ($method === 'GET' && $path === '/') {
        redirect('/boards/free/posts');
    }

    if ($method === 'GET' && $path === '/register') {
        show_register();
        return;
    }
    if ($method === 'POST' && $path === '/register') {
        handle_register();
    }

    if ($method === 'GET' && $path === '/login') {
        show_login();
        return;
    }
    if ($method === 'POST' && $path === '/login') {
        handle_login();
    }

    if ($method === 'POST' && $path === '/logout') {
        handle_logout();
    }

    if ($method === 'GET' && $path === '/users') {
        list_users();
        return;
    }

    if ($path === '/posts') {
        if ($method === 'GET') {
            list_posts((string) ($_GET['board'] ?? 'free'));
            return;
        }
        if ($method === 'POST') {
            create_post((string) ($_POST['board'] ?? 'free'));
        }
    }

    if ($method === 'GET' && $path === '/posts/new') {
        show_new_post((string) ($_GET['board'] ?? 'free'));
        return;
    }

    if (preg_match('#^/boards/([A-Za-z0-9_-]+)/posts$#', $path, $matches)) {
        if ($method === 'GET') {
            list_posts($matches[1]);
            return;
        }
        if ($method === 'POST') {
            create_post($matches[1]);
        }
    }

    if ($method === 'GET' && preg_match('#^/boards/([A-Za-z0-9_-]+)/posts/new$#', $path, $matches)) {
        show_new_post($matches[1]);
        return;
    }

    if (preg_match('#^/posts/(\d+)$#', $path, $matches)) {
        $id = (int) $matches[1];
        if ($method === 'GET') {
            show_post($id);
            return;
        }
        if ($method === 'PUT') {
            update_post($id);
        }
        if ($method === 'DELETE') {
            delete_post($id);
        }
    }

    if ($method === 'GET' && preg_match('#^/posts/(\d+)/edit$#', $path, $matches)) {
        show_edit_post((int) $matches[1]);
        return;
    }

    if ($method === 'POST' && preg_match('#^/posts/(\d+)/comments$#', $path, $matches)) {
        add_comment((int) $matches[1]);
    }

    if ($method === 'POST' && preg_match('#^/posts/(\d+)/files$#', $path, $matches)) {
        upload_files_to_post((int) $matches[1]);
    }

    if (preg_match('#^/comments/(\d+)$#', $path, $matches)) {
        $id = (int) $matches[1];
        if ($method === 'PUT') {
            update_comment($id);
        }
        if ($method === 'DELETE') {
            delete_comment($id);
        }
    }

    if ($method === 'GET' && preg_match('#^/files/(\d+)$#', $path, $matches)) {
        download_file((int) $matches[1]);
    }

    if ($method !== 'GET') {
        abort_request(405, '이 경로에서 사용할 수 없는 메서드입니다.');
    }

    abort_request(404, '요청한 페이지를 찾을 수 없습니다.');
} catch (HttpException $exception) {
    render_error($exception->status, $exception->getMessage());
} catch (Throwable $exception) {
    error_log((string) $exception);
    render_error(500, '서버 오류가 발생했습니다. 잠시 후 다시 시도해 주세요.');
}
