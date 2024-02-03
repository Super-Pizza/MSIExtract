use std::{collections::HashMap, fs};

fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let file = args.last().unwrap();
    let dir = file.trim_end_matches(".msi").to_owned() + "_tmp";
    let data = std::fs::read(file).unwrap();
    fs::create_dir(dir.clone()).unwrap_or_default();
    if data[0..8] != [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1] {
        panic!("Invalid header!")
    }
    let version = u16::from_le_bytes([data[26], data[27]]);
    let sector_size = if version == 3 {
        if data[30..32] != [0x09, 0x00] {
            panic!("Invalid shift")
        }
        512
    } else if version == 4 {
        if data[30..32] != [0x0c, 0x00] {
            panic!("Invalid shift")
        }
        4096
    } else {
        panic!("Invalid version")
    };
    let _num_dirs = get_u32(&data, 40);
    let _num_fats = get_u32(&data, 44);
    let mut first_dir = get_u32(&data, 48);
    let mut first_mini = get_u32(&data, 60);
    let _num_mini = get_u32(&data, 64);
    let mut first_difat = get_u32(&data, 68);
    let _num_difat = get_u32(&data, 72);
    let mut difat = vec![];
    for i in 0..109 {
        let difat_entry = get_u32(&data, 76 + 4 * i);
        if difat_entry != 0xFFFFFFFF {
            difat.push(difat_entry)
        }
    }
    while first_difat != 0xFFFFFFFE {
        for i in 0..sector_size / 4 - 1 {
            let difat_entry = get_u32(&data, sector_size * (first_difat as usize + 1) + i * 4);
            if difat_entry != 0xFFFFFFFF {
                difat.push(difat_entry)
            }
        }
        first_difat = get_u32(&data, sector_size * (first_difat as usize + 1));
    }
    let mut fat = vec![];
    for sector in difat {
        for i in 0..sector_size / 4 {
            fat.push(get_u32(&data, sector_size * (sector as usize + 1) + i * 4))
        }
    }
    let mut mini_fat = vec![];
    while first_mini != 0xFFFFFFFE {
        for i in 0..sector_size / 4 {
            mini_fat.push(get_u32(
                &data,
                sector_size * (first_mini as usize + 1) + i * 4,
            ));
        }
        first_mini = fat[first_mini as usize];
    }
    let mut mini_stream = vec![];
    let mut cabs = vec![];
    while first_dir != 0xFFFFFFFE {
        for i in 0..sector_size / 128 {
            let base = sector_size * (first_dir as usize + 1) + i * 128;
            let mut sector = get_u32(&data, base + 116);
            if data[base + 66] == 0x05 {
                while sector != 0xFFFFFFFE {
                    mini_stream.append(
                        &mut data[sector_size * (sector as usize + 1)
                            ..sector_size * (sector as usize + 2)]
                            .to_owned(),
                    );
                    sector = fat[sector as usize];
                }
                continue;
            }
            if data[base + 66] == 0x01 || data[base + 66] == 0x0 {
                continue;
            }
            let name_len = get_u16(&data, base + 64);
            let mut name_u16 = vec![];
            for i in 0..name_len / 2 {
                name_u16.push(get_u16(&data, base + 2 * i as usize));
            }
            let name = if name_u16.iter().all(|&c| c < 0x3800) {
                String::from_utf16(&name_u16)
                    .unwrap()
                    .trim_end_matches('\0')
                    .trim_start_matches('\x05')
                    .to_owned()
            } else {
                String::from_utf8(
                    name_u16
                        .iter()
                        .flat_map(|&c| {
                            const MAP: &[u8] =
                                b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._";
                            if c == 0 {
                                return vec![];
                            }
                            if c == 0x4840 {
                                return vec![];
                            }
                            let c = c - 0x3800;
                            let c1 = c & 0x3F;
                            let c2 = c >> 6;
                            let mut res = vec![MAP[c1 as usize]];
                            if c2 == 0x40 {
                                return res;
                            }
                            res.push(MAP[c2 as usize]);
                            res
                        })
                        .collect::<Vec<_>>(),
                )
                .unwrap()
            };
            let mut size = get_u64(&data, base + 120);
            if version == 3 {
                size &= 0xffffffff;
            }
            let mut file_data = vec![];
            if size < 4096 {
                while sector != 0xFFFFFFFE {
                    file_data.append(
                        &mut mini_stream[64 * sector as usize..64 * (sector as usize + 1)]
                            .to_owned(),
                    );
                    sector = mini_fat[sector as usize];
                }
            } else {
                while sector != 0xFFFFFFFE {
                    file_data.append(
                        &mut data[sector_size * (sector as usize + 1)
                            ..sector_size * (sector as usize + 2)]
                            .to_owned(),
                    );
                    sector = fat[sector as usize];
                }
            }
            fs::write(dir.clone() + "/" + &name, &file_data[0..size as usize]).unwrap();
            if name.contains(".cab") {
                let parent = std::path::Path::new(&dir)
                    .parent()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned();
                fs::copy(dir.clone() + "/" + &name, parent.clone() + "/" + &name).unwrap();
                cabs.push(parent.clone() + "/" + &name);
            }
        }
        first_dir = fat[first_dir as usize];
    }
    // Now, extract & rename those files!
    let strings = fs::read(dir.clone() + "/_StringData").unwrap();
    let string_infos = fs::read(dir.clone() + "/_StringPool").unwrap();
    let mut offset = 0;
    let mut string_list = vec![String::new()];
    for i in 1..string_infos.len() / 4 {
        let len = get_u16(&string_infos, i * 4);
        let data = String::from_utf8(strings[offset..offset + len as usize].to_owned()).unwrap();
        string_list.push(data);
        offset += len as usize;
    }
    let columns = fs::read(dir.clone() + "/_Columns").unwrap();
    let row_count = columns.len() / 8;
    let mut column_list = vec![];
    for i in 0..row_count {
        let table = get_u16(&columns, i * 2);
        let number = get_u16(&columns, i * 2 + row_count * 2);
        let name = get_u16(&columns, i * 2 + row_count * 4);
        let ty = get_u16(&columns, i * 2 + row_count * 6);
        column_list.push((table, number, name, ty));
    }
    let files = fs::read(dir.clone() + "/File").unwrap();
    let columns = get_columns("File", &string_list, &column_list);
    let row_length = columns.last().unwrap().1 + columns.last().unwrap().2;
    let row_count = files.len() / row_length as usize;
    let mut file_names = HashMap::new();
    for i in 0..row_count {
        let file_offs = get_val(&files, i, 0, row_count, 2);
        let filename_offs = get_val(&files, i, columns[2].1 as usize, row_count, 2);
        println!(
            "File: {} = {}",
            string_list[file_offs as usize], string_list[filename_offs as usize]
        );
        let filename = &string_list[filename_offs as usize];
        file_names.insert(
            string_list[file_offs as usize].as_str(),
            filename
                .split_once('|')
                .map(|v| v.1)
                .unwrap_or(filename)
                .to_owned(),
        );
    }
    if let Ok(media) = fs::read(dir.clone() + "/Media") {
        println!("Searching for cabinets...");
        let columns = get_columns("Media", &string_list, &column_list);
        let row_length = columns.last().unwrap().1 + columns.last().unwrap().2;
        let row_count = media.len() / row_length as usize;
        for i in 0..row_count {
            let cabinet = get_val(&media, i, columns[3].1 as usize, row_count, 2);
            let cab_name = string_list[cabinet as usize].clone();
            if !cab_name.starts_with('#') && !cab_name.is_empty() {
                println!("Found cabinet: {cab_name}");
                let path = std::path::Path::new(&dir)
                    .parent()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned();
                cabs.push(path + "/" + &cab_name);
            }
        }
    }
    for cab in cabs {
        println!("Extracting cabinet: {cab}");
        fs::create_dir(cab.trim_end_matches(".cab")).unwrap();
        let mut cabinet = cab::Cabinet::new(fs::File::open(&cab).unwrap()).unwrap();
        for (path, name) in &file_names {
            println!("{name}");
            if let Ok(mut reader) = cabinet.read_file(path) {
                let mut writer =
                    fs::File::create(cab.trim_end_matches(".cab").to_owned() + "/" + &name)
                        .unwrap();
                std::io::copy(&mut reader, &mut writer).unwrap();
            }
        }
    }
    fs::remove_dir_all(dir).unwrap();
}
fn get_u64(data: &[u8], offs: usize) -> u64 {
    u64::from_le_bytes([
        data[offs],
        data[offs + 1],
        data[offs + 2],
        data[offs + 3],
        data[offs + 4],
        data[offs + 5],
        data[offs + 6],
        data[offs + 7],
    ])
}
fn get_u32(data: &[u8], offs: usize) -> u32 {
    u32::from_le_bytes([data[offs], data[offs + 1], data[offs + 2], data[offs + 3]])
}

fn get_u16(data: &[u8], offs: usize) -> u16 {
    u16::from_le_bytes([data[offs], data[offs + 1]])
}

fn get_val(data: &[u8], row: usize, column_offs: usize, row_count: usize, size: usize) -> u32 {
    if size == 2 {
        get_u16(data, row * 2 + row_count * column_offs) as u32
    } else {
        get_u32(data, row * 2 + row_count * column_offs)
    }
}

fn get_columns(
    name: &str,
    strings: &[String],
    column_list: &[(u16, u16, u16, u16)],
) -> Vec<(u16, u16, u16)> {
    let mut table_columns = column_list
        .iter()
        .filter(|&v| strings[v.0 as usize] == name)
        .collect::<Vec<_>>();

    table_columns.sort_by_key(|&v| v.1);
    table_columns
        .iter()
        .scan(0, |i, &v| {
            let size = if v.3 & 0xefff == 0x0900 || v.3 & 0x0800 == 0x0800 {
                2
            } else {
                (v.3 & 0xff).max(2)
            };
            let old = *i;
            *i += size;
            Some((v.2, old, size))
        })
        .collect::<Vec<_>>()
}
