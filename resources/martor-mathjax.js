jQuery(function ($) {
    $(document).on('martor:preview', function (e, $content) {
        let promise = Promise.resolve()

        function update_math(code) {
            promise = promise.then(
                () => MathJax.typesetPromise(code()))
                .catch((err) => console.log('Typeset failed: ' + err.message))
            return promise
        }

        update_math(() => {
            return [$content[0]]
        })
    })
});