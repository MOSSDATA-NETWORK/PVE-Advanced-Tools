//! 内置前端：build.rs 在编译时把 backend/static 打进二进制（构建时没有该目录则为空表）
use axum::{body::Body, http::header, response::Response};

include!(concat!(env!("OUT_DIR"), "/web_ui.rs"));

/// 按与 main.rs 磁盘回退相同的规则返回内置页面；files 须按路径排序（build.rs 已排序）
pub fn response(files: &[(&str, &'static [u8])], path: &str) -> Response {
    if path.contains("..") || path.contains('\0') {
        return Response::builder().status(400).body(Body::from("Bad Request")).unwrap();
    }
    let find = |name: &str| files.binary_search_by(|(p, _)| (*p).cmp(name)).ok().map(|i| files[i].1);
    let rel = path.trim_start_matches('/');
    if let Some(bytes) = find(rel) {
        // 带 hash 的 assets 永久缓存；其他文件与 index.html 相同策略禁缓存
        let cache = if path.starts_with("/assets/") {
            "public, max-age=31536000, immutable"
        } else {
            "no-cache, no-store, must-revalidate"
        };
        return Response::builder()
            .header(header::CONTENT_TYPE, mime_guess::from_path(rel).first_or_octet_stream().as_ref())
            .header(header::CACHE_CONTROL, cache)
            .body(Body::from(bytes))
            .unwrap();
    }
    // 资产缺失必须真 404——回退成 index.html 会让 JS 加载到 HTML 而白屏
    if path.starts_with("/assets/") {
        return Response::builder().status(404).body(Body::from("Not Found")).unwrap();
    }
    // 其余路径交给前端路由（SPA）
    Response::builder()
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-cache, no-store, must-revalidate")
        .body(Body::from(find("index.html").unwrap_or(b"<h1>index.html not found</h1>")))
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::response;

    const FILES: &[(&str, &[u8])] = &[
        ("assets/app-1.js", b"js"),
        ("favicon.svg", b"svg"),
        ("index.html", b"<div id=\"app\"></div>"),
    ];
    const NO_STORE: &str = "no-cache, no-store, must-revalidate";

    async fn get(files: &[(&str, &'static [u8])], path: &str) -> (u16, String, String, Vec<u8>) {
        let r = response(files, path);
        let header = |name| r.headers().get(name).map(|v| v.to_str().unwrap().to_string()).unwrap_or_default();
        let (status, content_type, cache) = (r.status().as_u16(), header("content-type"), header("cache-control"));
        let body = axum::body::to_bytes(r.into_body(), usize::MAX).await.unwrap().to_vec();
        (status, content_type, cache, body)
    }

    fn index(body: &[u8]) -> (u16, String, String, Vec<u8>) {
        (200, "text/html; charset=utf-8".into(), NO_STORE.into(), body.to_vec())
    }

    #[tokio::test]
    async fn serves_like_the_disk_fallback() {
        assert!(FILES.windows(2).all(|w| w[0].0 < w[1].0), "test table must be sorted like build.rs output");
        let spa = index(b"<div id=\"app\"></div>");
        assert_eq!(get(FILES, "/").await, spa);
        assert_eq!(get(FILES, "/hosts/3").await, spa);
        assert_eq!(get(FILES, "/assets").await, spa);
        assert_eq!(get(FILES, "/assets/app-1.js").await,
            (200, "text/javascript".into(), "public, max-age=31536000, immutable".into(), b"js".to_vec()));
        assert_eq!(get(FILES, "/favicon.svg").await,
            (200, "image/svg+xml".into(), NO_STORE.into(), b"svg".to_vec()));
        assert_eq!(get(FILES, "/index.html").await,
            (200, "text/html".into(), NO_STORE.into(), b"<div id=\"app\"></div>".to_vec()));
        assert_eq!(get(FILES, "/assets/gone.js").await, (404, String::new(), String::new(), b"Not Found".to_vec()));
        assert_eq!(get(FILES, "/../etc/passwd").await, (400, String::new(), String::new(), b"Bad Request".to_vec()));
        assert_eq!(get(FILES, "/a\0b").await.0, 400);
    }

    #[tokio::test]
    async fn missing_index_is_reported_not_served_as_empty() {
        let files: &[(&str, &[u8])] = &[("assets/app-1.js", b"js")];
        assert_eq!(get(files, "/").await, index(b"<h1>index.html not found</h1>"));
    }
}
