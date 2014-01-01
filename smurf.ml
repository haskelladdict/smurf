(* smurf is a tool for checking filesystem permissions *)
open Core.Std


(** is_suid tests for the suid flag in a stats structure *)
let is_suid file_info = (land) file_info.Unix.st_perm 0o4000 <> 0 


(** is_sgid tests for the sgid flag in a stats structure *)
let is_sgid file_info = (land) file_info.Unix.st_perm 0o2000 <> 0 



(** is_gwrt tests if a file is group writable via a stats structure *)
let is_ord file_info = (land) file_info.Unix.st_perm 0o0400 <> 0 



(** is_gwrt tests if a file is group writable via a stats structure *)
let is_owrt file_info = (land) file_info.Unix.st_perm 0o0200 <> 0 



(** is_gwrt tests if a file is group writable via a stats structure *)
let is_oexe file_info = (land) file_info.Unix.st_perm 0o0100 <> 0 



(** is_gwrt tests if a file is group writable via a stats structure *)
let is_grd file_info = (land) file_info.Unix.st_perm 0o0040 <> 0 



(** is_gwrt tests if a file is group writable via a stats structure *)
let is_gwrt file_info = (land) file_info.Unix.st_perm 0o0020 <> 0 



(** is_gwrt tests if a file is group writable via a stats structure *)
let is_gexe file_info = (land) file_info.Unix.st_perm 0o0010 <> 0 


(** is_gwrt tests if a file is group writable via a stats structure *)
let is_wrd file_info = (land) file_info.Unix.st_perm 0o0004 <> 0 



(** is_gwrt tests if a file is group writable via a stats structure *)
let is_wwrt file_info = (land) file_info.Unix.st_perm 0o0002 <> 0 



(** is_gwrt tests if a file is group writable via a stats structure *)
let is_wexe file_info = (land) file_info.Unix.st_perm 0o0001 <> 0 



(** has_bad_permissions takes a stats structure and returns
 * true if it detects improper permissions and false otherwise *)
let has_bad_permissions file_info = 
  if is_suid file_info 
  || is_sgid file_info 
  || is_gwrt file_info 
  || is_wwrt file_info then
    true
  else
    false



(** check_dir_entries checks the file/directory entries for bad
 * file permissions and also picks up new directories to be scanned *)
let rec check_dir_entries entries dirs acc =
  match entries with
  | []    -> (acc, dirs)
  | c::cs -> 
    try
      let file_info = Unix.lstat c in
      match file_info.st_kind with
      | S_DIR when (c <> "/proc" && c <> "/sys") -> 
          check_dir_entries cs (c::dirs) acc

      | S_REG when (has_bad_permissions file_info) ->
          check_dir_entries cs dirs ((c,file_info)::acc)

      | _ -> check_dir_entries cs dirs acc

     with
      _ -> check_dir_entries cs dirs acc



(** scan_directories scans all directories in dirs and builds up a
 * list of tagged files with improper permissions *)
let rec scan_directories acc = function
  | []    -> acc
  | d::ds -> 
    try
      let entries = List.map ~f:(fun n -> Filename.concat d n) (Sys.ls_dir(d)) in
      let (tagged_files, dirs) = check_dir_entries entries ds acc in
        scan_directories tagged_files dirs

    with
      _ -> scan_directories acc ds



(** add_uids_gids scans /etc/passwd and /etc/group and extracts and adds 
 * the user and group names for all files with bad permissions *)
let rec add_uids_gids acc = function
  | [] -> acc
  | (path, info) :: xs -> 
      let uid    = info.Unix.st_uid in
      let uentry = Unix.Passwd.getbyuid_exn uid in
      let uname  = uentry.name in
      let gid    = info.Unix.st_gid in
      let gentry = Unix.Group.getbygid_exn gid in
      let gname  = gentry.name in
        add_uids_gids ((path, info, uname, gname)::acc) xs



(** st_perm_to_string converts a numerical value stat's file permission
 * entry to a ls type string (rwxrwxrwx) *)
let st_perm_to_string perms =
  let regular_conv   = ["r";"w";"x";"r";"w";"x";"r";"w";"x"] in
  let suid_conv      = ["r";"w";"s";"r";"w";"x";"r";"w";"x"] in
  let sgid_conv      = ["r";"w";"x";"r";"w";"s";"r";"w";"x"] in
  let suid_sgid_conv = ["r";"w";"s";"r";"w";"s";"r";"w";"x"] in
  let testers        = [is_ord; is_owrt; is_oexe; is_grd; is_gwrt; is_gexe;
                        is_wrd; is_wwrt; is_wexe] in
  let converter = 
    if is_suid perms && is_sgid perms then
      suid_sgid_conv
    else
      if is_suid perms then
        suid_conv
      else
        if is_sgid perms then
          sgid_conv
        else
          regular_conv
  in

  let out_string = List.fold_left ~init:[] ~f:(fun acc (t,c) -> 
    if t perms then 
      (c::acc) 
    else ("-"::acc)) 
    (List.zip_exn testers converter) 
  in
    String.concat ~sep:"" (List.rev out_string)



(** stat_to_time_string extracts the time from a stat record and 
 * returns it as a string *)
let stat_to_time_string info =
  (Unix.strftime (Unix.localtime info.Unix.st_mtime) "%d %b %Y %T") 



(** print_permission_scan_results print the results of the permission scan *)
let print_permission_scan_results suid_files sgid_files gwrt_files wwrt_files =
  let print_fun (path, info, uname, gname) = printf "%s %-8s %-8s %s %s\n" 
    (st_perm_to_string info) uname gname (stat_to_time_string info) path
  in

  printf "\n*********************** files with suid set *****************\n";
  List.iter suid_files ~f:print_fun;

  printf "\n*********************** files with guid set *****************\n";
  List.iter sgid_files ~f:print_fun;

  printf "\n*********************** group writable files ****************\n";
  List.iter gwrt_files ~f:print_fun;

  printf "\n*********************** world writable files ***************\n";
  List.iter wwrt_files ~f:print_fun;;



(** start_scan is the top level scanner firing of the recursive scanning *)
let start_permission_scan dir_list =
  (*let root = "/" in*)
  (*let dir_list = [root] in*)
  let files = scan_directories [] dir_list |> add_uids_gids [] in
  let suid_files = List.filter ~f:(fun (_, i, _, _) -> is_suid i) files in
  let sgid_files = List.filter ~f:(fun (_, i, _, _) -> is_sgid i) files in
  let gwrt_files = List.filter ~f:(fun (_, i, _, _) -> is_gwrt i) files in
  let wwrt_files = List.filter ~f:(fun (_, i, _, _) -> is_wwrt i) files in
  print_permission_scan_results suid_files sgid_files gwrt_files wwrt_files



(** command line parsing code *)

(** specs for command line parsing *)
let command =
  Command.basic 
    ~summary:"smurf is a filesystem permission checker"
    Command.Spec.(
      empty
      +> flag "-p" no_arg ~doc:"permission permission scan"
    )
    begin
      fun perm_scan () -> 
        if perm_scan then
          start_permission_scan ["/"]
        else
          ()
    end


let () =
  Command.run command
