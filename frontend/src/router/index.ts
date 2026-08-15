import { createRouter, createWebHistory } from 'vue-router'
import DashboardView from '@/views/DashboardView.vue'
import PkiOverviewView from '@/views/PkiOverviewView.vue'
import CertificatesView from '@/views/CertificatesView.vue'
import GatewaysView from '@/views/GatewaysView.vue'
import DiscoveryView from '@/views/DiscoveryView.vue'
import PoliciesView from '@/views/PoliciesView.vue'
import SettingsView from '@/views/SettingsView.vue'

const routes = [
  {
    path: '/',
    name: 'dashboard',
    component: DashboardView,
  },
  {
    path: '/pki',
    name: 'pki',
    component: PkiOverviewView,
  },
  {
    path: '/certificates',
    name: 'certificates',
    component: CertificatesView,
  },
  {
    path: '/gateways',
    name: 'gateways',
    component: GatewaysView,
  },
  {
    path: '/discovery',
    name: 'discovery',
    component: DiscoveryView,
  },
  {
    path: '/policies',
    name: 'policies',
    component: PoliciesView,
  },
  {
    path: '/settings',
    name: 'settings',
    component: SettingsView,
  },
]

export const router = createRouter({
  history: createWebHistory(),
  routes,
})
