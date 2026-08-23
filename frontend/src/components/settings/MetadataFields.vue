<script setup lang="ts">
import { computed, ref } from 'vue'
import { Archive, Plus, X } from 'lucide-vue-next'
import { useApi } from '@/composables/useApi'
import { useAsyncData } from '@/composables/useAsyncData'
import { useAuthStore } from '@/stores/auth'
import PanelBox from '@/components/ui/PanelBox.vue'
import type { ListResponse, MetadataField, MetadataFieldType, MetadataOption } from '@/lib/types'

/**
 * Defining what every certificate is asked.
 *
 * What a PKI team slices its inventory by belongs to that team — cost centre,
 * change ticket, data classification, which product line — and a fixed schema
 * guesses at that list and is wrong for every organisation.
 *
 * Admin-only, because a required field changes what everyone else must supply
 * before they can get a certificate at all.
 */

const api = useApi()
const auth = useAuthStore()

const fields = useAsyncData<ListResponse<MetadataField>>((s) =>
  api.get<ListResponse<MetadataField>>('/api/v1/metadata-fields?include_archived=true', s),
)

const active = computed(() => (fields.data.value?.data ?? []).filter((f) => !f.is_archived))
const archived = computed(() => (fields.data.value?.data ?? []).filter((f) => f.is_archived))

const TYPE_LABELS: Record<MetadataFieldType, string> = {
  TEXT: 'Free text',
  SELECT: 'One of a list',
  MULTI_SELECT: 'Any of a list',
  BOOLEAN: 'Yes or no',
}

// ── The editor ────────────────────────────────────────────

const editing = ref<MetadataField | null>(null)
const creating = ref(false)
const saving = ref(false)
const error = ref<string | null>(null)

const form = ref({
  label: '',
  field_type: 'TEXT' as MetadataFieldType,
  display: 'DROPDOWN' as 'DROPDOWN' | 'RADIO',
  help_text: '',
  is_required: false,
  sort_order: 0,
  options: [] as MetadataOption[],
})

const needsOptions = computed(
  () => form.value.field_type === 'SELECT' || form.value.field_type === 'MULTI_SELECT',
)

function startCreate() {
  editing.value = null
  creating.value = true
  error.value = null
  form.value = {
    label: '',
    field_type: 'TEXT',
    display: 'DROPDOWN',
    help_text: '',
    is_required: false,
    sort_order: active.value.length + 1,
    options: [],
  }
}

function startEdit(field: MetadataField) {
  creating.value = false
  editing.value = field
  error.value = null
  form.value = {
    label: field.label,
    field_type: field.field_type,
    display: field.display,
    help_text: field.help_text ?? '',
    is_required: field.is_required,
    sort_order: field.sort_order,
    // Copied, and the values carried with them. An option's value is what
    // certificates already hold; dropping it here and letting the server
    // re-derive one from the label would silently reclassify every one of them
    // the moment somebody fixes a typo.
    options: field.options.map((o) => ({ ...o })),
  }
}

function cancel() {
  editing.value = null
  creating.value = false
  error.value = null
}

const newOption = ref('')

function addOption() {
  const label = newOption.value.trim()
  if (!label) return
  // No value: the server derives one for a new option and preserves it for an
  // existing one.
  form.value.options.push({ value: '', label })
  newOption.value = ''
}

function removeOption(index: number) {
  form.value.options.splice(index, 1)
}

async function save() {
  saving.value = true
  error.value = null
  try {
    const body = {
      label: form.value.label,
      field_type: form.value.field_type,
      display: form.value.display,
      help_text: form.value.help_text,
      is_required: form.value.is_required,
      sort_order: Number(form.value.sort_order) || 0,
      options: needsOptions.value ? form.value.options : [],
      is_archived: false,
    }
    if (editing.value) {
      await api.put(`/api/v1/metadata-fields/${editing.value.id}`, body)
    } else {
      await api.post('/api/v1/metadata-fields', body)
    }
    cancel()
    await fields.refresh()
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  } finally {
    saving.value = false
  }
}

async function archive(field: MetadataField) {
  error.value = null
  try {
    await api.delete(`/api/v1/metadata-fields/${field.id}`)
    await fields.refresh()
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  }
}

async function restore(field: MetadataField) {
  error.value = null
  try {
    await api.put(`/api/v1/metadata-fields/${field.id}`, {
      label: field.label,
      field_type: field.field_type,
      display: field.display,
      help_text: field.help_text ?? '',
      is_required: field.is_required,
      sort_order: field.sort_order,
      options: field.options,
      is_archived: false,
    })
    await fields.refresh()
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  }
}
</script>

<template>
  <PanelBox label="Certificate metadata" :note="`${active.length} fields`">
    <div class="flex flex-col gap-3 min-w-0">
      <p class="field-help">
        Questions every certificate can answer, so the inventory can be sorted and filtered by
        what matters here rather than by what CertPilot guessed. Required fields must be answered
        before a certificate is issued.
      </p>

      <p v-if="error" role="alert" class="meta-error">{{ error }}</p>

      <table v-if="active.length" class="tbl">
        <thead>
          <tr>
            <th>Field</th>
            <th>Type</th>
            <th>Answers</th>
            <th>Required</th>
            <th class="num">Actions</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="field in active" :key="field.id">
            <td class="cell-primary">
              {{ field.label }}
              <span class="meta-key">{{ field.key }}</span>
            </td>
            <td>{{ TYPE_LABELS[field.field_type] }}</td>
            <td class="meta-options">
              <template v-if="field.options.length">
                {{ field.options.map((o) => o.label).join(' · ') }}
              </template>
              <template v-else-if="field.field_type === 'BOOLEAN'">Yes · No</template>
              <template v-else>Anything</template>
            </td>
            <td>{{ field.is_required ? 'Yes' : '—' }}</td>
            <td class="num whitespace-nowrap">
              <button v-if="auth.isAdmin" class="btn-console" @click="startEdit(field)">Edit</button>
              <button
                v-if="auth.isAdmin"
                class="btn-console ml-1"
                title="Stop offering this field. Values already recorded are kept."
                @click="archive(field)"
              >
                <Archive class="w-3 h-3" />
              </button>
            </td>
          </tr>
        </tbody>
      </table>

      <p v-else class="field-help">
        No fields are defined. Certificates carry only their environment, team and tags.
      </p>

      <div v-if="auth.isAdmin && !creating && !editing">
        <button class="btn-console" data-variant="signal" @click="startCreate">
          <Plus class="w-3 h-3" /> Add a field
        </button>
      </div>

      <!-- Editor -->
      <div v-if="creating || editing" class="editor">
        <div class="grid gap-2 sm:grid-cols-2">
          <div class="field">
            <label class="label-micro" for="mf-label">Label</label>
            <input
              id="mf-label"
              v-model="form.label"
              type="text"
              class="input-console"
              placeholder="Cost centre"
            />
            <p v-if="editing" class="field-help">
              Stored under <code>{{ editing.key }}</code
              >, which never changes — renaming the label rewrites nothing.
            </p>
          </div>

          <div class="field">
            <label class="label-micro" for="mf-type">Type</label>
            <select
              id="mf-type"
              v-model="form.field_type"
              class="input-console"
              :disabled="!!editing"
            >
              <option v-for="(label, value) in TYPE_LABELS" :key="value" :value="value">
                {{ label }}
              </option>
            </select>
            <!-- Not editable after creation: certificates already hold values in
                 the old shape, and changing the type leaves them unreadable
                 rather than merely stale. -->
            <p v-if="editing" class="field-help">
              Fixed after creation. Archive this field and add a new one to change it.
            </p>
          </div>
        </div>

        <div v-if="needsOptions" class="field">
          <label class="label-micro">Options</label>
          <div v-if="form.options.length" class="option-list">
            <span v-for="(option, index) in form.options" :key="index" class="option-chip">
              {{ option.label }}
              <button type="button" title="Remove" @click="removeOption(index)">
                <X class="w-3 h-3" />
              </button>
            </span>
          </div>
          <div class="flex gap-1">
            <input
              v-model="newOption"
              type="text"
              class="input-console flex-1"
              placeholder="Tier 1"
              @keydown.enter.prevent="addOption"
            />
            <button type="button" class="btn-console" @click="addOption">Add</button>
          </div>
          <p class="field-help">
            Removing an option stops it being offered. Certificates already holding it keep it.
          </p>
        </div>

        <div v-if="form.field_type === 'SELECT'" class="field">
          <label class="label-micro">Shown as</label>
          <div class="flex gap-1">
            <button
              v-for="mode in (['DROPDOWN', 'RADIO'] as const)"
              :key="mode"
              type="button"
              class="btn-console"
              :data-variant="form.display === mode ? 'signal' : undefined"
              @click="form.display = mode"
            >
              {{ mode === 'DROPDOWN' ? 'Dropdown' : 'Radio buttons' }}
            </button>
          </div>
        </div>

        <div class="field">
          <label class="label-micro" for="mf-help">Help text</label>
          <input
            id="mf-help"
            v-model="form.help_text"
            type="text"
            class="input-console"
            placeholder="Finance code this certificate is billed to"
          />
        </div>

        <div class="flex items-center gap-4 flex-wrap">
          <label class="flex items-center gap-2 cursor-pointer" style="font-size: var(--fs-small)">
            <input v-model="form.is_required" type="checkbox" />
            Required to issue a certificate
          </label>
          <div class="flex items-center gap-2">
            <label class="label-micro" for="mf-order">Order</label>
            <input
              id="mf-order"
              v-model="form.sort_order"
              type="number"
              class="input-console w-16"
            />
          </div>
        </div>
        <!-- Stated because the alternative reading — that ticking this
             invalidates the estate — is the one people reasonably fear. -->
        <p v-if="form.is_required" class="field-help">
          Applies to new requests only. Certificates already issued stay valid and editable.
        </p>

        <div class="flex justify-end gap-2">
          <button class="btn-console" @click="cancel">Cancel</button>
          <button class="btn-console" data-variant="signal" :disabled="saving" @click="save">
            {{ saving ? 'Saving…' : editing ? 'Save changes' : 'Create field' }}
          </button>
        </div>
      </div>

      <!-- Archived -->
      <details v-if="archived.length" class="archived">
        <summary class="label-rail">Archived ({{ archived.length }})</summary>
        <p class="field-help">
          No longer offered on new certificates. Kept so the values already recorded against them
          still have a label.
        </p>
        <ul class="archived-list">
          <li v-for="field in archived" :key="field.id">
            <span>{{ field.label }}</span>
            <span class="meta-key">{{ field.key }}</span>
            <button v-if="auth.isAdmin" class="btn-console" @click="restore(field)">Restore</button>
          </li>
        </ul>
      </details>
    </div>
  </PanelBox>
</template>

<style scoped>
.meta-key {
  font-size: var(--fs-micro);
  color: var(--text-muted);
  margin-left: 0.375rem;
}

.meta-options {
  max-width: 22rem;
  overflow: hidden;
  text-overflow: ellipsis;
}

.meta-error {
  padding: 0.375rem 0.625rem;
  font-size: var(--fs-small);
  background: var(--sev-critical-wash);
  border-left: 3px solid var(--sev-critical);
  word-break: break-word;
}

.editor {
  display: flex;
  flex-direction: column;
  gap: 0.625rem;
  padding: 0.75rem;
  background: var(--ink-raised);
  border: 1px solid var(--line-strong);
}

.field {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
  min-width: 0;
}

.option-list {
  display: flex;
  flex-wrap: wrap;
  gap: 0.25rem;
}

.option-chip {
  display: inline-flex;
  align-items: center;
  gap: 0.3rem;
  padding: 0.15rem 0.4rem;
  font-size: var(--fs-small);
  background: var(--ink-page);
  border: 1px solid var(--line-strong);
}

.option-chip button {
  display: inline-flex;
  color: var(--text-muted);
  background: none;
  border: 0;
  cursor: pointer;
}

.option-chip button:hover {
  color: var(--sev-critical);
}

.archived summary {
  cursor: pointer;
  padding: 0.25rem 0;
}

.archived-list {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
  margin-top: 0.25rem;
}

.archived-list li {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-size: var(--fs-small);
  color: var(--text-muted);
}
</style>
