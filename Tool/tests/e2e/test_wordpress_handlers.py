"""The registration resolver against the real WP Download Manager 3.2.33 tree.

The answer key below was written by reading the plugin's `add_action` and
`register_rest_route` calls, not by running the resolver. Needs Docker (ctags)
and the plugin source under ``Targets/wordpress/src``.
"""

from __future__ import annotations

import pytest

from dast_orchestrator.adapters import targets
from dast_orchestrator.context import code_context as cc
from dast_orchestrator.context import dispatch

pytestmark = pytest.mark.e2e

_NS = "WPDM\\"
#: registration file -> class, {action or REST route: handler method or None}.
#: None marks a registration that is commented out in the source (a phantom
#: endpoint Noir 1.2.1 still emits) or whose callback the plugin never defines.
ANSWERS = {
    "src/__/Apply.php": ("__\\Apply", {
        "showLockOptions": "showLockOptions", "wpdm_verify_file_pass": "checkFilePassword",
        "wpdm_generate_password": "generatePassword",
        "wpdm-activate-shop": "activatePremiumPackage",
        "clear_cache": "clearCache", "clear_stats": "clearStats"}),
    "src/Admin/Menu/Settings.php": ("Admin\\Menu\\Settings", {
        "wpdm_settings": "loadSettingsPage"}),
    "src/Admin/Menu/Templates.php": ("Admin\\Menu\\Templates", {
        "template_preview": "preview", "wpdm_save_email_template": "saveEmailTemplate",
        "update_template_status": "updateTemplateStatus",
        "wpdm_save_email_setting": "saveEmailSetting",
        "connect_template_server": "templateServer"}),
    "src/Admin/AdminController.php": ("Admin\\AdminController", {
        "wpdm_remove_admin_notice": "removeNotices",
        "hide_wpdmpro_notice": "hideProNotice"}),
    "src/Admin/Menu/Stats.php": ("Admin\\Menu\\Stats", {
        "wpdm_stats_get_packages": "ajax_callback_get_packages",
        "wpdm_stats_get_users": "ajax_callback_get_users"}),
    "src/Admin/Menu/Packages.php": ("Admin\\Menu\\Packages", {
        "wpdm_admin_upload_file": "uploadFile"}),
    "src/User/Login.php": ("User\\Login", {
        "updatePassword": "updatePassword", "resetPassword": "resetPassword"}),
    "src/AssetManager/AssetManager.php": ("AssetManager\\AssetManager", {
        "wpdm_fm_file_upload": None,
        "wpdm_mkdir": "mkDir", "wpdm_newfile": "newFile", "wpdm_scandir": "scanDir",
        "wpdm_createzip": "createZip", "wpdm_unzipit": "unZip",
        "wpdm_openfile": "openFile", "wpdm_filesettings": "fileSettings",
        "wpdm_unlink": "deleteItem", "wpdm_rename": "renameItem",
        "wpdm_savefile": "saveFile", "wpdm_copypaste": "copyItem",
        "wpdm_cutpaste": "moveItem", "wpdm_addcomment": "addComment",
        "wpdm_newsharelink": "addShareLink", "wpdm_getlinkdet": "getLinkDet",
        "wpdm_updatelink": "updateLink", "wpdm_deletelink": "deleteLink"}),
    "src/MediaLibrary/MediaAccessControl.php": ("MediaLibrary\\MediaAccessControl", {
        "wpdm_media_pass": "makeMediaPass", "wpdm_media_access": "mediaAccessControl",
        "make_media_public": "makeMediaPublic", "make_media_private": "makeMediaPrivate"}),
}
REST = {
    ("GET", "/wp-json/wpdm/media-access", "src/MediaLibrary/RestAPI.php"):
        "MediaLibrary\\RestAPI::mediaAccess",
    ("GET", "/wp-json/wpdm/v1/create-term", "src/MediaLibrary/RestAPI.php"): None,
    ("GET", "/wp-json/wpdm/v1/link-templates", "src/MediaLibrary/RestAPI.php"): None,
    ("GET", "/wp-json/wpdm/v1/categories", "src/MediaLibrary/RestAPI.php"): None,
    ("POST", "/wp-json/wpdm/validate-captcha", "src/Package/RestAPI.php"):
        "Package\\PackageLocks::validateCaptcha",
    ("POST", "/wp-json/wpdm/validate-password", "src/Package/RestAPI.php"):
        "Package\\PackageLocks::validatePassword",
    ("POST", "/wp-json/wpdm/email-to-download", "src/Package/RestAPI.php"): None,
    ("GET", "/wp-json/wpdm/search", "src/Package/RestAPI.php"):
        "Package\\PackageController::search",
}


def _cases():
    for rel, (cls, actions) in ANSWERS.items():
        for action, method in actions.items():
            for verb in ("GET", "POST"):
                yield (verb, f"/wp-admin/admin-ajax.php?action={action}", rel,
                       f"{_NS}{cls}::{method}" if method else None)
    for (verb, path, rel), handler in REST.items():
        yield verb, path, rel, f"{_NS}{handler}" if handler else None


@pytest.fixture(scope="module")
def wordpress(docker_available):
    if not docker_available:
        pytest.skip("Docker is not available (ctags builds the index)")
    target = targets.get("wordpress")
    source = targets.target_source(target)
    if not (source / "src").is_dir():
        pytest.skip("WordPress plugin source not unzipped under Targets/wordpress/src")
    c = target.code_context
    return cc.load_or_build_index(source, c.scope, c.languages, c.kinds), source


def test_the_answer_key_covers_noirs_90_endpoints():
    assert len(list(_cases())) == 90


@pytest.mark.parametrize("verb, path, rel, expected", list(_cases()),
                         ids=lambda v: str(v)[-40:])
def test_every_wordpress_endpoint_resolves_to_its_registered_handler(
        wordpress, verb, path, rel, expected):
    index, source = wordpress
    endpoint = {"method": verb, "path": path, "technology": "php_wordpress",
                "code_paths": [{"path": f"/src/{rel}", "line": 0}]}
    found = dispatch.locate_handler(endpoint, index, source)
    assert (found.symbol.qualified if found.symbol else None) == expected, found.reason
