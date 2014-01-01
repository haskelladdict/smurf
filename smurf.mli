open Core.Std

(** helper functions for extracting file properties from a stats
 * structure *)
val is_suid : UnixLabels.LargeFile.stats -> bool
val is_sgid : UnixLabels.LargeFile.stats -> bool
val is_ord : UnixLabels.LargeFile.stats -> bool
val is_owrt : UnixLabels.LargeFile.stats -> bool
val is_oexe : UnixLabels.LargeFile.stats -> bool
val is_grd : UnixLabels.LargeFile.stats -> bool
val is_gwrt : UnixLabels.LargeFile.stats -> bool
val is_gexe : UnixLabels.LargeFile.stats -> bool
val is_wrd : UnixLabels.LargeFile.stats -> bool
val is_wwrt : UnixLabels.LargeFile.stats -> bool
val is_wexe : UnixLabels.LargeFile.stats -> bool


(** has_bad_permissions takes a stats structure and returns                   
 * true if it detects improper permissions and false otherwise *)
val has_bad_permissions : UnixLabels.LargeFile.stats -> bool
