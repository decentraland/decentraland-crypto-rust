(function() {var type_impls = {
"dcl_crypto":[["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Clone-for-EIP1271Signature\" class=\"impl\"><a class=\"src rightside\" href=\"src/dcl_crypto/account.rs.html#483\">source</a><a href=\"#impl-Clone-for-EIP1271Signature\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"dcl_crypto/account/struct.EIP1271Signature.html\" title=\"struct dcl_crypto::account::EIP1271Signature\">EIP1271Signature</a></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.clone\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/dcl_crypto/account.rs.html#483\">source</a><a href=\"#method.clone\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.76.0/core/clone/trait.Clone.html#tymethod.clone\" class=\"fn\">clone</a>(&amp;self) -&gt; <a class=\"struct\" href=\"dcl_crypto/account/struct.EIP1271Signature.html\" title=\"struct dcl_crypto::account::EIP1271Signature\">EIP1271Signature</a></h4></section></summary><div class='docblock'>Returns a copy of the value. <a href=\"https://doc.rust-lang.org/1.76.0/core/clone/trait.Clone.html#tymethod.clone\">Read more</a></div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.clone_from\" class=\"method trait-impl\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.0.0\">1.0.0</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/1.76.0/src/core/clone.rs.html#169\">source</a></span><a href=\"#method.clone_from\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.76.0/core/clone/trait.Clone.html#method.clone_from\" class=\"fn\">clone_from</a>(&amp;mut self, source: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.76.0/std/primitive.reference.html\">&amp;Self</a>)</h4></section></summary><div class='docblock'>Performs copy-assignment from <code>source</code>. <a href=\"https://doc.rust-lang.org/1.76.0/core/clone/trait.Clone.html#method.clone_from\">Read more</a></div></details></div></details>","Clone","dcl_crypto::account::EIP1654Signature"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-TryFrom%3CString%3E-for-EIP1271Signature\" class=\"impl\"><a class=\"src rightside\" href=\"src/dcl_crypto/account.rs.html#509-515\">source</a><a href=\"#impl-TryFrom%3CString%3E-for-EIP1271Signature\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;<a class=\"struct\" href=\"https://doc.rust-lang.org/1.76.0/alloc/string/struct.String.html\" title=\"struct alloc::string::String\">String</a>&gt; for <a class=\"struct\" href=\"dcl_crypto/account/struct.EIP1271Signature.html\" title=\"struct dcl_crypto::account::EIP1271Signature\">EIP1271Signature</a></h3></section></summary><div class=\"impl-items\"><details class=\"toggle\" open><summary><section id=\"associatedtype.Error\" class=\"associatedtype trait-impl\"><a href=\"#associatedtype.Error\" class=\"anchor\">§</a><h4 class=\"code-header\">type <a href=\"https://doc.rust-lang.org/1.76.0/core/convert/trait.TryFrom.html#associatedtype.Error\" class=\"associatedtype\">Error</a> = <a class=\"enum\" href=\"dcl_crypto/account/enum.DecodeHexError.html\" title=\"enum dcl_crypto::account::DecodeHexError\">DecodeHexError</a></h4></section></summary><div class='docblock'>The type returned in the event of a conversion error.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.try_from\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/dcl_crypto/account.rs.html#512-514\">source</a><a href=\"#method.try_from\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.76.0/core/convert/trait.TryFrom.html#tymethod.try_from\" class=\"fn\">try_from</a>(value: <a class=\"struct\" href=\"https://doc.rust-lang.org/1.76.0/alloc/string/struct.String.html\" title=\"struct alloc::string::String\">String</a>) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/1.76.0/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;Self, Self::<a class=\"associatedtype\" href=\"https://doc.rust-lang.org/1.76.0/core/convert/trait.TryFrom.html#associatedtype.Error\" title=\"type core::convert::TryFrom::Error\">Error</a>&gt;</h4></section></summary><div class='docblock'>Performs the conversion.</div></details></div></details>","TryFrom<String>","dcl_crypto::account::EIP1654Signature"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Deserialize%3C'de%3E-for-EIP1271Signature\" class=\"impl\"><a class=\"src rightside\" href=\"src/dcl_crypto/account.rs.html#483\">source</a><a href=\"#impl-Deserialize%3C'de%3E-for-EIP1271Signature\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.196/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for <a class=\"struct\" href=\"dcl_crypto/account/struct.EIP1271Signature.html\" title=\"struct dcl_crypto::account::EIP1271Signature\">EIP1271Signature</a></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.deserialize\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/dcl_crypto/account.rs.html#483\">source</a><a href=\"#method.deserialize\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://docs.rs/serde/1.0.196/serde/de/trait.Deserialize.html#tymethod.deserialize\" class=\"fn\">deserialize</a>&lt;__D&gt;(__deserializer: __D) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/1.76.0/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;Self, __D::<a class=\"associatedtype\" href=\"https://docs.rs/serde/1.0.196/serde/de/trait.Deserializer.html#associatedtype.Error\" title=\"type serde::de::Deserializer::Error\">Error</a>&gt;<div class=\"where\">where\n    __D: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.196/serde/de/trait.Deserializer.html\" title=\"trait serde::de::Deserializer\">Deserializer</a>&lt;'de&gt;,</div></h4></section></summary><div class='docblock'>Deserialize this value from the given Serde deserializer. <a href=\"https://docs.rs/serde/1.0.196/serde/de/trait.Deserialize.html#tymethod.deserialize\">Read more</a></div></details></div></details>","Deserialize<'de>","dcl_crypto::account::EIP1654Signature"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Serialize-for-EIP1271Signature\" class=\"impl\"><a class=\"src rightside\" href=\"src/dcl_crypto/account.rs.html#483\">source</a><a href=\"#impl-Serialize-for-EIP1271Signature\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"trait\" href=\"https://docs.rs/serde/1.0.196/serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for <a class=\"struct\" href=\"dcl_crypto/account/struct.EIP1271Signature.html\" title=\"struct dcl_crypto::account::EIP1271Signature\">EIP1271Signature</a></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.serialize\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/dcl_crypto/account.rs.html#483\">source</a><a href=\"#method.serialize\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://docs.rs/serde/1.0.196/serde/ser/trait.Serialize.html#tymethod.serialize\" class=\"fn\">serialize</a>&lt;__S&gt;(&amp;self, __serializer: __S) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/1.76.0/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;__S::<a class=\"associatedtype\" href=\"https://docs.rs/serde/1.0.196/serde/ser/trait.Serializer.html#associatedtype.Ok\" title=\"type serde::ser::Serializer::Ok\">Ok</a>, __S::<a class=\"associatedtype\" href=\"https://docs.rs/serde/1.0.196/serde/ser/trait.Serializer.html#associatedtype.Error\" title=\"type serde::ser::Serializer::Error\">Error</a>&gt;<div class=\"where\">where\n    __S: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.196/serde/ser/trait.Serializer.html\" title=\"trait serde::ser::Serializer\">Serializer</a>,</div></h4></section></summary><div class='docblock'>Serialize this value into the given Serde serializer. <a href=\"https://docs.rs/serde/1.0.196/serde/ser/trait.Serialize.html#tymethod.serialize\">Read more</a></div></details></div></details>","Serialize","dcl_crypto::account::EIP1654Signature"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-__Deref-for-EIP1271Signature\" class=\"impl\"><a class=\"src rightside\" href=\"src/dcl_crypto/account.rs.html#487-492\">source</a><a href=\"#impl-__Deref-for-EIP1271Signature\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/ops/deref/trait.Deref.html\" title=\"trait core::ops::deref::Deref\">Deref</a> for <a class=\"struct\" href=\"dcl_crypto/account/struct.EIP1271Signature.html\" title=\"struct dcl_crypto::account::EIP1271Signature\">EIP1271Signature</a></h3></section></summary><div class=\"impl-items\"><details class=\"toggle\" open><summary><section id=\"associatedtype.Target\" class=\"associatedtype trait-impl\"><a href=\"#associatedtype.Target\" class=\"anchor\">§</a><h4 class=\"code-header\">type <a href=\"https://doc.rust-lang.org/1.76.0/core/ops/deref/trait.Deref.html#associatedtype.Target\" class=\"associatedtype\">Target</a> = <a class=\"struct\" href=\"https://doc.rust-lang.org/1.76.0/alloc/vec/struct.Vec.html\" title=\"struct alloc::vec::Vec\">Vec</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.76.0/std/primitive.u8.html\">u8</a>&gt;</h4></section></summary><div class='docblock'>The resulting type after dereferencing.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.deref\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/dcl_crypto/account.rs.html#489-491\">source</a><a href=\"#method.deref\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.76.0/core/ops/deref/trait.Deref.html#tymethod.deref\" class=\"fn\">deref</a>(&amp;self) -&gt; &amp;Self::<a class=\"associatedtype\" href=\"https://doc.rust-lang.org/1.76.0/core/ops/deref/trait.Deref.html#associatedtype.Target\" title=\"type core::ops::deref::Deref::Target\">Target</a></h4></section></summary><div class='docblock'>Dereferences the value.</div></details></div></details>","Deref","dcl_crypto::account::EIP1654Signature"],["<section id=\"impl-StructuralPartialEq-for-EIP1271Signature\" class=\"impl\"><a class=\"src rightside\" href=\"src/dcl_crypto/account.rs.html#483\">source</a><a href=\"#impl-StructuralPartialEq-for-EIP1271Signature\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/marker/trait.StructuralPartialEq.html\" title=\"trait core::marker::StructuralPartialEq\">StructuralPartialEq</a> for <a class=\"struct\" href=\"dcl_crypto/account/struct.EIP1271Signature.html\" title=\"struct dcl_crypto::account::EIP1271Signature\">EIP1271Signature</a></h3></section>","StructuralPartialEq","dcl_crypto::account::EIP1654Signature"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Display-for-EIP1271Signature\" class=\"impl\"><a class=\"src rightside\" href=\"src/dcl_crypto/account.rs.html#494-498\">source</a><a href=\"#impl-Display-for-EIP1271Signature\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/fmt/trait.Display.html\" title=\"trait core::fmt::Display\">Display</a> for <a class=\"struct\" href=\"dcl_crypto/account/struct.EIP1271Signature.html\" title=\"struct dcl_crypto::account::EIP1271Signature\">EIP1271Signature</a></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.fmt\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/dcl_crypto/account.rs.html#495-497\">source</a><a href=\"#method.fmt\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.76.0/core/fmt/trait.Display.html#tymethod.fmt\" class=\"fn\">fmt</a>(&amp;self, f: &amp;mut <a class=\"struct\" href=\"https://doc.rust-lang.org/1.76.0/core/fmt/struct.Formatter.html\" title=\"struct core::fmt::Formatter\">Formatter</a>&lt;'_&gt;) -&gt; <a class=\"type\" href=\"https://doc.rust-lang.org/1.76.0/core/fmt/type.Result.html\" title=\"type core::fmt::Result\">Result</a></h4></section></summary><div class='docblock'>Formats the value using the given formatter. <a href=\"https://doc.rust-lang.org/1.76.0/core/fmt/trait.Display.html#tymethod.fmt\">Read more</a></div></details></div></details>","Display","dcl_crypto::account::EIP1654Signature"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-TryFrom%3C%26str%3E-for-EIP1271Signature\" class=\"impl\"><a class=\"src rightside\" href=\"src/dcl_crypto/account.rs.html#500-507\">source</a><a href=\"#impl-TryFrom%3C%26str%3E-for-EIP1271Signature\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;&amp;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.76.0/std/primitive.str.html\">str</a>&gt; for <a class=\"struct\" href=\"dcl_crypto/account/struct.EIP1271Signature.html\" title=\"struct dcl_crypto::account::EIP1271Signature\">EIP1271Signature</a></h3></section></summary><div class=\"impl-items\"><details class=\"toggle\" open><summary><section id=\"associatedtype.Error\" class=\"associatedtype trait-impl\"><a href=\"#associatedtype.Error\" class=\"anchor\">§</a><h4 class=\"code-header\">type <a href=\"https://doc.rust-lang.org/1.76.0/core/convert/trait.TryFrom.html#associatedtype.Error\" class=\"associatedtype\">Error</a> = <a class=\"enum\" href=\"dcl_crypto/account/enum.DecodeHexError.html\" title=\"enum dcl_crypto::account::DecodeHexError\">DecodeHexError</a></h4></section></summary><div class='docblock'>The type returned in the event of a conversion error.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.try_from\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/dcl_crypto/account.rs.html#503-506\">source</a><a href=\"#method.try_from\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.76.0/core/convert/trait.TryFrom.html#tymethod.try_from\" class=\"fn\">try_from</a>(value: &amp;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.76.0/std/primitive.str.html\">str</a>) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/1.76.0/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;Self, Self::<a class=\"associatedtype\" href=\"https://doc.rust-lang.org/1.76.0/core/convert/trait.TryFrom.html#associatedtype.Error\" title=\"type core::convert::TryFrom::Error\">Error</a>&gt;</h4></section></summary><div class='docblock'>Performs the conversion.</div></details></div></details>","TryFrom<&str>","dcl_crypto::account::EIP1654Signature"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Debug-for-EIP1271Signature\" class=\"impl\"><a class=\"src rightside\" href=\"src/dcl_crypto/account.rs.html#483\">source</a><a href=\"#impl-Debug-for-EIP1271Signature\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/fmt/trait.Debug.html\" title=\"trait core::fmt::Debug\">Debug</a> for <a class=\"struct\" href=\"dcl_crypto/account/struct.EIP1271Signature.html\" title=\"struct dcl_crypto::account::EIP1271Signature\">EIP1271Signature</a></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.fmt\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/dcl_crypto/account.rs.html#483\">source</a><a href=\"#method.fmt\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.76.0/core/fmt/trait.Debug.html#tymethod.fmt\" class=\"fn\">fmt</a>(&amp;self, f: &amp;mut <a class=\"struct\" href=\"https://doc.rust-lang.org/1.76.0/core/fmt/struct.Formatter.html\" title=\"struct core::fmt::Formatter\">Formatter</a>&lt;'_&gt;) -&gt; <a class=\"type\" href=\"https://doc.rust-lang.org/1.76.0/core/fmt/type.Result.html\" title=\"type core::fmt::Result\">Result</a></h4></section></summary><div class='docblock'>Formats the value using the given formatter. <a href=\"https://doc.rust-lang.org/1.76.0/core/fmt/trait.Debug.html#tymethod.fmt\">Read more</a></div></details></div></details>","Debug","dcl_crypto::account::EIP1654Signature"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-PartialEq-for-EIP1271Signature\" class=\"impl\"><a class=\"src rightside\" href=\"src/dcl_crypto/account.rs.html#483\">source</a><a href=\"#impl-PartialEq-for-EIP1271Signature\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/cmp/trait.PartialEq.html\" title=\"trait core::cmp::PartialEq\">PartialEq</a> for <a class=\"struct\" href=\"dcl_crypto/account/struct.EIP1271Signature.html\" title=\"struct dcl_crypto::account::EIP1271Signature\">EIP1271Signature</a></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.eq\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/dcl_crypto/account.rs.html#483\">source</a><a href=\"#method.eq\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.76.0/core/cmp/trait.PartialEq.html#tymethod.eq\" class=\"fn\">eq</a>(&amp;self, other: &amp;<a class=\"struct\" href=\"dcl_crypto/account/struct.EIP1271Signature.html\" title=\"struct dcl_crypto::account::EIP1271Signature\">EIP1271Signature</a>) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.76.0/std/primitive.bool.html\">bool</a></h4></section></summary><div class='docblock'>This method tests for <code>self</code> and <code>other</code> values to be equal, and is used\nby <code>==</code>.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.ne\" class=\"method trait-impl\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.0.0\">1.0.0</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/1.76.0/src/core/cmp.rs.html#242\">source</a></span><a href=\"#method.ne\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.76.0/core/cmp/trait.PartialEq.html#method.ne\" class=\"fn\">ne</a>(&amp;self, other: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.76.0/std/primitive.reference.html\">&amp;Rhs</a>) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.76.0/std/primitive.bool.html\">bool</a></h4></section></summary><div class='docblock'>This method tests for <code>!=</code>. The default implementation is almost always\nsufficient, and should not be overridden without very good reason.</div></details></div></details>","PartialEq","dcl_crypto::account::EIP1654Signature"]]
};if (window.register_type_impls) {window.register_type_impls(type_impls);} else {window.pending_type_impls = type_impls;}})()