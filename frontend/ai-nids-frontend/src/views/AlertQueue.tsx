import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { fetchAlerts, acknowledgeAlert } from '../api/alert';

export default function AlertQueue() {
  const queryClient = useQueryClient();
  const [filters, setFilters] = useState({});

  const { data, isLoading, error } = useQuery({
    queryKey: ['alerts', filters],
    queryFn: () => fetchAlerts(filters),
    staleTime: 10_000,
    refetchInterval: 30_000,
  });

  const { mutate: ack } = useMutation({
    mutationFn: acknowledgeAlert,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['alerts'] }),
  });

  if (isLoading) return <div>Loading alerts...</div>;
  if (error) return <div>Error loading alerts</div>;

  return (
    <div>
      <h1>Alert Queue</h1>
    </div>
  );
}