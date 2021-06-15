# ofb

idapython plugin

- get binary offset from current image/module base and copy to clipboard

![Alt text](img/1.png "Title")

![Alt text](img/2.png "Title")

- jump to an offset from current image/module base (Shift + G)

![Alt text](img/3.png "Title")

- change current name to string pattern that supports offset. default: `{name}_{offset}`

![Alt text](img/4.png "Title")

![Alt text](img/5.png "Title")

- work in both debuging & analysing mode

useful for sharing offset with other people or different IDA remote debug & static analysis view.

# instruction

Copy `ofb.py` to `plugins` directory of IDA

---

*Optional:* To change the default template, fix constant `NAME_TEMPLATE` in `ofb.py`. Only support
- `{name}` => your input name
- `{offset}` => offset from base

Eg: `zzz_{offset}_{name}` => `zzz_a0b1_Myname`
