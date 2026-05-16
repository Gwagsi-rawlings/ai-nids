import { useQuery } from '@tanstack/react-query';
import { fetchTrafficStats } from '../api/capture';

// your existing code below...

const { data: stats } = useQuery({
  queryKey: ['traffic', 'stats'],
  queryFn: fetchTrafficStats,
  staleTime: 5_000,
  refetchInterval: 5_000,   // Every 5s — served from Redis cache
});