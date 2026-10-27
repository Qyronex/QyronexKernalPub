from pathlib import Path

page = Path("kernel/page-table-aarch64/src/implementation.rs")
text = page.read_text()
old = """            if entry & VALID == 0 {
                continue;
            }
"""
new = """            if entry == 0 {
                continue;
            }
            if entry & VALID == 0 {
                return Err(Error::InvalidDescriptor);
            }
"""
if text.count(old) < 2:
    raise SystemExit("expected two empty-tree traversal anchors")
page.write_text(text.replace(old, new, 2))

activation = Path("kernel/process-aarch64/src/activation.rs")
text = activation.read_text()
old = """        let handle = process.address_space_handle();
        let mut released = 0usize;
        loop {
            let Some(vma) = self.user_vma_at(process, objects, handle, 0)? else {
                return Ok(released);
            };
            if !matches!(vma.backing, kernal_vm::Backing::Anonymous) {
                self.poison();
                return Err(Error::UnsupportedExitBacking);
            }

            let frame = match self
                .unmap_user_page_coalescing_anonymous(process, objects, handle, backend, vma.start)
            {
                Ok(frame) => frame,
                Err(_) => {
                    self.poison();
                    return Err(Error::ExitCleanupFailed);
                }
            };
            if !release(frame) {
                self.poison();
                return Err(Error::ExitCleanupFailed);
            }
            released = match released.checked_add(1) {
                Some(next) => next,
                None => {
                    self.poison();
                    return Err(Error::ExitCleanupFailed);
                }
            };
        }
"""
new = """        let handle = process.address_space_handle();
        let mut released = 0usize;
        while let Some(vma) = self.user_vma_at(process, objects, handle, 0)? {
            if !matches!(vma.backing, kernal_vm::Backing::Anonymous) {
                self.poison();
                return Err(Error::UnsupportedExitBacking);
            }

            let frame = match self
                .unmap_user_page_coalescing_anonymous(process, objects, handle, backend, vma.start)
            {
                Ok(frame) => frame,
                Err(_) => {
                    self.poison();
                    return Err(Error::ExitCleanupFailed);
                }
            };
            if !release(frame) {
                self.poison();
                return Err(Error::ExitCleanupFailed);
            }
            released = match released.checked_add(1) {
                Some(next) => next,
                None => {
                    self.poison();
                    return Err(Error::ExitCleanupFailed);
                }
            };
        }

        if unsafe {
            kernal_address_space_aarch64::Aarch64AddressSpaceExt::reclaim_empty_page_table_tree(
                &mut self.space,
                backend,
            )
        }
        .is_err()
        {
            self.poison();
            return Err(Error::ExitCleanupFailed);
        }
        Ok(released)
"""
if text.count(old) != 1:
    raise SystemExit("unexpected successful superseded reclaim loop")
activation.write_text(text.replace(old, new, 1))
