use extanalyzer::download::chrome::ChromeDownloader;

#[test]
fn test_chrome_download_url_generation() {
    let downloader = ChromeDownloader::new();
    let url = downloader.build_download_url("nkbihfbeogaeaoehlefnkodbefgpgknn");

    assert!(url.contains("clients2.google.com"));
    assert!(url.contains("nkbihfbeogaeaoehlefnkodbefgpgknn"));
}
