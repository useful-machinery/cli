use std::fs;
use std::os::unix::fs::PermissionsExt as _;

use rustix::fs::{RenameFlags, renameat_with};

use super::*;

#[test]
fn staged_root_stays_writable_until_renamed_and_sealed() {
    let temporary = tempfile::tempdir().expect("create tree parent");
    let parent: OwnedFd = File::open(temporary.path())
        .expect("open tree parent")
        .into();
    mkdir(&parent, "staged").expect("create staged root");
    let root = open_directory_at(&parent, "staged").expect("open staged root");
    let workflow = TreeFile {
        bytes: b"workflow".as_slice().into(),
        executable: false,
    };
    let command = TreeFile {
        bytes: b"command".as_slice().into(),
        executable: true,
    };
    write_tree_contents(
        &root,
        [("workflow.yaml", &workflow), ("bin/command", &command)].into_iter(),
        &["programs".to_owned()],
    )
    .expect("write tree contents");

    let mode = |relative: &str| {
        fs::metadata(temporary.path().join(relative))
            .expect("inspect tree entry")
            .permissions()
            .mode()
            & 0o777
    };
    let staged_mode = mode("staged");
    assert_eq!(mode("staged/workflow.yaml"), 0o444);
    assert_eq!(mode("staged/bin"), 0o555);
    assert_eq!(mode("staged/bin/command"), 0o555);
    assert_eq!(mode("staged/programs"), 0o555);
    renameat_with(&parent, "staged", &parent, "placed", RenameFlags::NOREPLACE)
        .expect("place tree");
    seal_directory(&root).expect("seal placed root");
    let placed_mode = mode("placed");

    for relative in ["placed", "placed/bin", "placed/programs"] {
        fs::set_permissions(
            temporary.path().join(relative),
            fs::Permissions::from_mode(0o700),
        )
        .expect("restore write permission for cleanup");
    }
    assert_eq!(staged_mode, 0o700);
    assert_eq!(placed_mode, 0o555);
}
