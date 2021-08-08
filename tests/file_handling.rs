use mrt_nom;
use std::path::Path;

static VIEW_DATA: &str = "data/latest-bview.gz";
static UPDATE_DATA: &str = "data/latest-update.gz";

#[test]
fn check_data_files_exists() {
    let mrt_view = Path::new(VIEW_DATA);

    assert!(mrt_view.exists(), "Input data file missing. Download it with: wget -P ./data/ http://data.ris.ripe.net/rrc25/latest-bview.gz");
}

#[test]
fn open_full_table_view() {

    let mrt_view = mrt_nom::read_gz_file(VIEW_DATA);
    assert!(mrt_view.is_ok(), "File successfully read and parsed from gz format");

}

#[test]
fn open_update_table_view() {

    let mrt_view = mrt_nom::read_gz_file(UPDATE_DATA);
    assert!(mrt_view.is_ok(), "File successfully read and parsed from gz format");

}
