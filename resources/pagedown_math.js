function mathjax_pagedown($) {
    if ('MathJax' in window && 'typesetPromise' in MathJax) {
        MathJax.typesetPromise()
    }
}

window.mathjax_pagedown = mathjax_pagedown;

$(window).on('load', function () {
    (mathjax_pagedown)('$' in window ? $ : django.jQuery);
});
