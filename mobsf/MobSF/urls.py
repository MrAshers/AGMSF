from django.urls import re_path

from mobsf.MobSF import utils
from mobsf.MobSF.security import (
    init_exec_hooks,
    store_exec_hashes_at_first_run,
)
from mobsf.MobSF.views import home
from mobsf.MobSF.views.api import api_static_analysis as api_sz
from mobsf.StaticAnalyzer import tests
from mobsf.StaticAnalyzer.views.common import (
    appsec,
    pdf,
    shared_func,
    suppression,
)
from mobsf.StaticAnalyzer.views.android import (
    find,
    manifest_view,
    source_tree,
    view_source,
)
from mobsf.StaticAnalyzer.views.android import static_analyzer as android_sa

from . import settings


urlpatterns = [
    # REST API
    # Static Analysis
    re_path(r'^api/v1/upload$', api_sz.api_upload),
    re_path(r'^api/v1/scan$', api_sz.api_scan),
    re_path(r'^api/v1/delete_scan$', api_sz.api_delete_scan),
    re_path(r'^api/v1/download_pdf$', api_sz.api_pdf_report),
    re_path(r'^api/v1/report_json$', api_sz.api_json_report),
    re_path(r'^api/v1/view_source$', api_sz.api_view_source,
            name='api_view_source'),
    re_path(r'^api/v1/scans$', api_sz.api_recent_scans),
    re_path(r'^api/v1/compare$', api_sz.api_compare),
    re_path(r'^api/v1/scorecard$', api_sz.api_scorecard),
    # Static Suppression
    re_path(r'^api/v1/suppress_by_rule$', api_sz.api_suppress_by_rule_id),
    re_path(r'^api/v1/suppress_by_files$', api_sz.api_suppress_by_files),
    re_path(r'^api/v1/list_suppressions$', api_sz.api_list_suppressions),
    re_path(r'^api/v1/delete_suppression$', api_sz.api_delete_suppression),
]
if settings.API_ONLY == '0':
    urlpatterns.extend([
        # General
        re_path(r'^$', home.index, name='home'),
        re_path(r'^upload/$', home.Upload.as_view),
        re_path(r'^download/', home.download, name='download'),
        re_path(r'^download_scan/', home.download_apk, name='download_scan'),
        re_path(r'^generate_downloads/$',
                home.generate_download,
                name='generate_downloads'),
        re_path(r'^about$', home.about, name='about'),
        re_path(r'^donate$', home.donate, name='donate'),
        re_path(r'^api_docs$', home.api_docs, name='api_docs'),
        re_path(r'^recent_scans/$', home.recent_scans, name='recent'),
        re_path(r'^delete_scan/$', home.delete_scan, name='delete_scan'),
        re_path(r'^search$', home.search),
        re_path(r'^error/$', home.error, name='error'),
        re_path(r'^not_found/$', home.not_found),
        re_path(r'^zip_format/$', home.zip_format),

        # Static Analysis
        # Android
        re_path(r'^static_analyzer/(?P<checksum>[0-9a-f]{32})/$',
                android_sa.static_analyzer,
                name='static_analyzer'),
        # Remove this is version 4/5
        re_path(r'^source_code/$', source_tree.run, name='tree_view'),
        re_path(r'^view_file/$', view_source.run, name='view_source'),
        re_path(r'^find/$', find.run, name='find_files'),
        re_path(r'^manifest_view/(?P<checksum>[0-9a-f]{32})/$',
                manifest_view.run,
                name='manifest_view'),

       # Shared
        re_path(r'^pdf/(?P<checksum>[0-9a-f]{32})/$', pdf.pdf, name='pdf'),
        re_path(r'^appsec_dashboard/(?P<checksum>[0-9a-f]{32})/$',
                appsec.appsec_dashboard,
                name='appsec_dashboard'),
        # Suppression
        re_path(r'^suppress_by_rule/$',
                suppression.suppress_by_rule_id,
                name='suppress_by_rule'),
        re_path(r'^suppress_by_files/$',
                suppression.suppress_by_files,
                name='suppress_by_files'),
        re_path(r'^list_suppressions/$',
                suppression.list_suppressions,
                name='list_suppressions'),
        re_path(r'^delete_suppression/$',
                suppression.delete_suppression,
                name='delete_suppression'),
        # App Compare
        re_path(r'^compare/(?P<hash1>[0-9a-f]{32})/(?P<hash2>[0-9a-f]{32})/$',
                shared_func.compare_apps),
        # Relative Shared & Dynamic Library scan
        re_path(r'^scan_library/(?P<checksum>[0-9a-f]{32})$',
                shared_func.scan_library,
                name='scan_library'),

        # Test
        re_path(r'^tests/$', tests.start_test),
    ])

utils.print_version()
init_exec_hooks()
store_exec_hashes_at_first_run()
