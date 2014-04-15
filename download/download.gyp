{
  'includes':[
    '../common/common.gypi',
  ],
  'targets': [
    {
      'target_name': 'tizen_download',
      'type': 'loadable_module',
      'sources': [
        'download_api.js',
        'download_context.cc',
        'download_context.h',
        'download_context_desktop.cc',
        'download_context_mobile.cc',
        'download_context_tizen.cc',
        'download_utils.h',
      ],
      
      'conditions': [
        ['tizen == 1', {
          'includes': [
            '../common/pkg-config.gypi',
          ],
          'ldflags': [
             '-L<(PRODUCT_DIR) -ltizen_filesystem',
            ],
          'variables': {
            'packages': [
              'capi-appfw-application',
              'capi-web-url-download',
            ]
          },
          'dependencies': [
           '../filesystem/filesystem.gyp:*',
          ],
         },
        ],
      ],
    },
  ],
}
