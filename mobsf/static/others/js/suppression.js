
  $(document).ready(function () {
    if (window.location.hash == '#suppression') {
      $("#supbtn").click();
    }
  });



  //Suppression Logic
  
  function slugify(str)
  {
  return str
    .toLowerCase()
    .trim()
    .replace(/[^\w\s-]/g, '')
    .replace(/[\s_-]+/g, '-')
    .replace(/^-+|-+$/g, '');
  }
  
  function escapeHtml(unsafe)
  {
    return unsafe
         .replace(/&/g, "&amp;")
         .replace(/</g, "&lt;")
         .replace(/>/g, "&gt;")
         .replace(/"/g, "&quot;")
         .replace(/'/g, "&#039;");
  }

  function action(url, data, on_success){
    //Add CSRF
    data.csrfmiddlewaretoken = csrf;
    $.ajax({
      url : url, 
      type : "POST",
      dataType: "json", 
      data : data,
      success : function(json){ on_success(json) },
      error : function(xhr, ajaxOptions, thrownError) {
        console.log(xhr.responseText);
      }
    });
  }

  function suppress(rule, files, tr, manifest=false){
    if (files){
      endpoint = suppress_by_files_url
      title = '<strong>从文件中忽略</strong>'
      html = `从现在开始，这将禁止这些文件触发 <b>${escapeHtml(pkg)}</b> 规则 <b>${escapeHtml(rule)}</b> 的任何结果。`
    } else {
      endpoint = suppress_by_rule_url
      title = '<strong>忽略规则</strong>'
      html = `从现在开始，这将禁止规则 <b>${escapeHtml(rule)}</b> 触发 <b>${escapeHtml(pkg)}</b> 。`
    }
    if (manifest){
      table = '#table_manifest'
      type = 'manifest'
    } else {
      table = '#table_code'
      type = 'code'
    }

    Swal.fire({
      title: title,
      type: 'warning',
      html: html,
      showCancelButton: true,
      cancelButtonText: '取消',
      confirmButtonText: '确定',
    }).then((result) => {
      if (result.value) {
        action(document.location.origin + endpoint,  { checksum: hash, rule, type }, function(json) {
            if (json.status==="ok") {
                $(table).DataTable().row(tr).remove().draw();
            } else {
              Swal.fire("Failed to Suppress")
            }
        });
      }
    });
      
  }

function remove_suppression(ctx){
  kind = $(ctx).data('kind');
  rule = $(ctx).data('rule');
  type = $(ctx).data('type');
  
  Swal.fire({
    title: '取消忽略规则?',
    type: 'warning',
    text: '你想取消忽略规则吗?',
    showCancelButton: true,
    cancelButtonText: '取消',
    confirmButtonText: '确定',
  }).then((result) => {
    if (result.value) {
      action(document.location.origin + delete_suppression_url, { checksum: hash, rule, kind, type }, function(json) {
          if (json.status==="ok") {
            window.location.hash = 'suppression';
            window.location.reload();
          } else {
            Swal.fire("Failed to remove suppression rule")
          }
      });
    }
  });

}

function get_rules(type, rules){
  var html = ''
  rules.forEach(element => {
    html += `${escapeHtml(element)} - <a onclick='remove_suppression(this)' data-rule='${escapeHtml(element)}' data-type='${type}' data-kind='rule'><i class="fa fa-trash fa-2xs"></i></a></br>`
  });
  return html
}


function get_files(type, files){
  var html = ''
  for (const [rule, rfiles] of Object.entries(files)) {
    html += `<b>${escapeHtml(rule)}</b> - <a onclick='remove_suppression(this)' data-rule='${escapeHtml(rule)}' data-type='${type}' data-kind='file'><i class="fa fa-trash fa-2xs"></i></a></br>`
    html += `<a class="btn btn-primary btn-sm" data-toggle="collapse" href="#c_${slugify(escapeHtml(rule))}" role="button" aria-expanded="false" aria-controls="c_${slugify(escapeHtml(rule))}">Files ➜</a><div class="collapse" id="c_${slugify(escapeHtml(rule))}"><div class="card card-body">`
    rfiles.forEach(element => {
      html += `<li>${escapeHtml(element)}</li>`
    });
    html += '</div></div></br>'
  }
  return html
}

function list_suppressions(){
  $(document).ready(function () {
    action(document.location.origin + list_suppressions_url, { checksum: hash }, function(json) {
      if (json.status==="ok") {

        var tbl = $('#sup_table').DataTable();
        tbl.clear().draw();
          $(function() {
              $.each(json.message, function(i, item) {
                typ = item.SUPPRESS_TYPE
                rule_ids = get_rules(typ, item.SUPPRESS_RULE_ID)
                files = get_files(typ, item.SUPPRESS_FILES)
                tbl.row.add([typ, rule_ids, files]).draw(false)
              });
          });
      } else {
        Swal.fire("Failed to list Suppression rules")
      }
    });
  });
}