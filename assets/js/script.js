$(function(){
    $('.downloadall').click(function(){
        $('.dz-preview.dz-success > a').each(function() {
            this.click();
        });
    });
});
