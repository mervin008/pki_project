<script setup lang="ts">
import { computed } from 'vue'
import type { MetadataField } from '@/lib/types'

/**
 * One metadata field, drawn according to its definition.
 *
 * All four types in one component because the alternative is four call sites
 * that each have to know the type vocabulary, and adding a fifth type would
 * mean finding all of them. The caller supplies a field and a value; how it is
 * drawn is the field's business.
 */
const props = defineProps<{
  field: MetadataField
  modelValue: unknown
}>()

const emit = defineEmits<{ (e: 'update:modelValue', value: unknown): void }>()

const inputId = computed(() => `meta-${props.field.key}`)

const selected = computed(() =>
  Array.isArray(props.modelValue) ? (props.modelValue as string[]) : [],
)

function toggleChoice(value: string) {
  const next = selected.value.includes(value)
    ? selected.value.filter((v) => v !== value)
    : [...selected.value, value]
  // An empty list is an absent value, not a stored []. The server treats them
  // the same way, and sending one shape while it stores another is how a form
  // ends up showing a value that is not there.
  emit('update:modelValue', next.length ? next : undefined)
}
</script>

<template>
  <div class="field">
    <label class="label-micro" :for="inputId">
      {{ field.label }}
      <span v-if="field.is_required" class="sev-warning">*</span>
    </label>

    <!-- TEXT -->
    <input
      v-if="field.field_type === 'TEXT'"
      :id="inputId"
      type="text"
      class="input-console"
      :value="(modelValue as string) ?? ''"
      @input="emit('update:modelValue', ($event.target as HTMLInputElement).value || undefined)"
    />

    <!-- BOOLEAN. Two explicit choices rather than a checkbox: a checkbox cannot
         express "not answered", and on a required field the difference between
         "no" and "nobody said" is the whole point of asking. -->
    <div v-else-if="field.field_type === 'BOOLEAN'" class="choices">
      <button
        v-for="choice in [
          { value: true, label: 'Yes' },
          { value: false, label: 'No' },
        ]"
        :key="String(choice.value)"
        type="button"
        class="choice"
        :data-active="modelValue === choice.value || undefined"
        @click="emit('update:modelValue', modelValue === choice.value ? undefined : choice.value)"
      >
        {{ choice.label }}
      </button>
    </div>

    <!-- SELECT, as radios -->
    <div v-else-if="field.field_type === 'SELECT' && field.display === 'RADIO'" class="choices">
      <button
        v-for="option in field.options"
        :key="option.value"
        type="button"
        class="choice"
        :data-active="modelValue === option.value || undefined"
        @click="emit('update:modelValue', modelValue === option.value ? undefined : option.value)"
      >
        {{ option.label }}
      </button>
    </div>

    <!-- SELECT, as a dropdown -->
    <select
      v-else-if="field.field_type === 'SELECT'"
      :id="inputId"
      class="input-console"
      :value="(modelValue as string) ?? ''"
      @change="emit('update:modelValue', ($event.target as HTMLSelectElement).value || undefined)"
    >
      <option value="">— not set —</option>
      <option v-for="option in field.options" :key="option.value" :value="option.value">
        {{ option.label }}
      </option>
    </select>

    <!-- MULTI_SELECT. Toggle buttons rather than a multiple-select box, which
         requires a modifier key nobody discovers and shows three rows of ten. -->
    <div v-else class="choices">
      <button
        v-for="option in field.options"
        :key="option.value"
        type="button"
        class="choice"
        :data-active="selected.includes(option.value) || undefined"
        @click="toggleChoice(option.value)"
      >
        {{ option.label }}
      </button>
    </div>

    <p v-if="field.help_text" class="field-help">{{ field.help_text }}</p>
  </div>
</template>

<style scoped>
.field {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
  min-width: 0;
}

.choices {
  display: flex;
  flex-wrap: wrap;
  gap: 1px;
  background: var(--line);
  border: 1px solid var(--line-strong);
  width: fit-content;
  max-width: 100%;
}

.choice {
  padding: 0.3rem 0.625rem;
  font-family: var(--font-mono);
  font-size: var(--fs-small);
  color: var(--text-muted);
  background: var(--ink-page);
  border: 0;
  cursor: pointer;
}

.choice:hover {
  color: var(--text-primary);
  background: var(--ink-hover);
}

.choice[data-active] {
  color: var(--text-primary);
  background: var(--ink-raised);
  box-shadow: inset 0 -2px 0 0 var(--signal);
}
</style>
